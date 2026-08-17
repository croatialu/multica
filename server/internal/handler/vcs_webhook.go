package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/integrations/vcs"
	"github.com/multica-ai/multica/server/internal/issuestatus"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// ── Response mappers ────────────────────────────────────────────────────────

// vcsPullRequestToResponse maps a stored VCS PR onto the shared PR response
// shape for single-PR webhook broadcasts (no aggregated check counts; the
// frontend re-queries the issue's PR list for fresh counts).
func vcsPullRequestToResponse(p db.VcsPullRequest) GitHubPullRequestResponse {
	return GitHubPullRequestResponse{
		ID:               uuidToString(p.ID),
		Provider:         p.Provider,
		WorkspaceID:      uuidToString(p.WorkspaceID),
		RepoOwner:        p.RepoOwner,
		RepoName:         p.RepoName,
		Number:           p.PrNumber,
		Title:            p.Title,
		State:            p.State,
		HtmlURL:          p.HtmlUrl,
		Branch:           textToPtr(p.Branch),
		AuthorLogin:      textToPtr(p.AuthorLogin),
		AuthorAvatarURL:  textToPtr(p.AuthorAvatarUrl),
		MergedAt:         timestampToPtr(p.MergedAt),
		ClosedAt:         timestampToPtr(p.ClosedAt),
		PRCreatedAt:      timestampToString(p.PrCreatedAt),
		PRUpdatedAt:      timestampToString(p.PrUpdatedAt),
		MergeableState:   nil,
		ChecksConclusion: nil,
		Additions:        p.Additions,
		Deletions:        p.Deletions,
		ChangedFiles:     p.ChangedFiles,
	}
}

// vcsPullRequestRowToResponse maps an issue's PR-list row, which carries the
// aggregated commit-status counts, onto the shared response shape.
func vcsPullRequestRowToResponse(p db.ListVCSPullRequestsByIssueRow) GitHubPullRequestResponse {
	return GitHubPullRequestResponse{
		ID:               uuidToString(p.ID),
		Provider:         p.Provider,
		WorkspaceID:      uuidToString(p.WorkspaceID),
		RepoOwner:        p.RepoOwner,
		RepoName:         p.RepoName,
		Number:           p.PrNumber,
		Title:            p.Title,
		State:            p.State,
		HtmlURL:          p.HtmlUrl,
		Branch:           textToPtr(p.Branch),
		AuthorLogin:      textToPtr(p.AuthorLogin),
		AuthorAvatarURL:  textToPtr(p.AuthorAvatarUrl),
		MergedAt:         timestampToPtr(p.MergedAt),
		ClosedAt:         timestampToPtr(p.ClosedAt),
		PRCreatedAt:      timestampToString(p.PrCreatedAt),
		PRUpdatedAt:      timestampToString(p.PrUpdatedAt),
		MergeableState:   nil,
		ChecksConclusion: aggregateChecksConclusion(p.ChecksFailed, p.ChecksPassed, p.ChecksPending, p.ChecksTotal),
		ChecksTotal:      p.ChecksTotal,
		ChecksPassed:     p.ChecksPassed,
		ChecksFailed:     p.ChecksFailed,
		ChecksPending:    p.ChecksPending,
		ChecksRunning:    p.ChecksPending,
		FailedCheckNames: []string{},
		Additions:        p.Additions,
		Deletions:        p.Deletions,
		ChangedFiles:     p.ChangedFiles,
	}
}

// ── Webhook ─────────────────────────────────────────────────────────────────

// HandleVCSWebhook (POST /api/webhooks/vcs/{connectionId}) authenticates and
// mirrors webhooks from any token-based Git provider. The connection id in the path
// selects the workspace, the provider, and the decryption secret; the provider
// adapter handles the provider-specific signature scheme, event header, and
// payload shape, returning normalized events to the shared mirror logic below.
func (h *Handler) HandleVCSWebhook(w http.ResponseWriter, r *http.Request) {
	// Where the integration is off (the managed cloud) the endpoint behaves as
	// if it does not exist — a bare 404 that reveals nothing about config, the
	// same response a genuinely unknown connection id gets below.
	if !h.isVCSAvailable() {
		writeError(w, http.StatusNotFound, "unknown connection")
		return
	}
	if !h.isVCSConfigured() {
		writeError(w, http.StatusServiceUnavailable, "vcs webhooks not configured")
		return
	}
	connUUID, ok := parseUUIDOrBadRequest(w, chi.URLParam(r, "connectionId"), "connection id")
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10 MiB cap
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body failed")
		return
	}

	conn, err := h.Queries.GetVCSConnectionByID(r.Context(), connUUID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("vcs: lookup connection failed", "err", err)
		}
		writeError(w, http.StatusNotFound, "unknown connection")
		return
	}
	provider, ok := vcs.For(conn.Provider)
	if !ok {
		slog.Error("vcs: connection has unknown provider", "provider", conn.Provider)
		writeError(w, http.StatusInternalServerError, "unknown provider")
		return
	}

	secret, err := h.openVCSSecret(conn.WebhookSecretEncrypted)
	if err != nil {
		slog.Error("vcs: decrypt webhook secret failed", "err", err)
		writeError(w, http.StatusInternalServerError, "secret error")
		return
	}
	if !provider.VerifySignature(secret, r.Header, body) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	switch provider.EventKind(r.Header) {
	case vcs.EventPullRequest:
		if pr, err := provider.ParsePullRequest(body); err != nil {
			slog.Warn("vcs: bad pull_request payload", "provider", conn.Provider, "err", err)
		} else {
			h.mirrorVCSPullRequest(r.Context(), conn, pr)
		}
	case vcs.EventCIStatus:
		if st, err := provider.ParseCIStatus(body); err != nil {
			slog.Warn("vcs: bad status payload", "provider", conn.Provider, "err", err)
		} else {
			h.mirrorVCSCIStatus(r.Context(), conn, st)
		}
	case vcs.EventReview:
		reviewProvider, supported := provider.(vcs.ReviewProvider)
		if !supported {
			break
		}
		review, parseErr := reviewProvider.ParseReview(body)
		if parseErr != nil {
			slog.Warn("vcs: bad review payload", "provider", conn.Provider, "err", parseErr)
			break
		}
		h.mirrorVCSReview(r.Context(), conn, reviewProvider, review)
	default:
		// Acknowledge unmodelled events so the provider doesn't flag the hook.
	}
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) mirrorVCSPullRequest(ctx context.Context, conn db.VcsConnection, ev vcs.PullRequestEvent) {
	if ev.RepoOwner == "" || ev.RepoName == "" || ev.Number == 0 {
		slog.Warn("vcs: pull_request missing repo identity", "provider", conn.Provider)
		return
	}

	pr, err := h.Queries.UpsertVCSPullRequest(ctx, db.UpsertVCSPullRequestParams{
		WorkspaceID:         conn.WorkspaceID,
		ConnectionID:        conn.ID,
		Provider:            conn.Provider,
		RepoOwner:           ev.RepoOwner,
		RepoName:            ev.RepoName,
		PrNumber:            ev.Number,
		Title:               ev.Title,
		State:               ev.State,
		HtmlUrl:             ev.HTMLURL,
		Branch:              ptrToText(strPtrOrNil(ev.Branch)),
		AuthorLogin:         ptrToText(strPtrOrNil(ev.AuthorLogin)),
		AuthorAvatarUrl:     ptrToText(strPtrOrNil(ev.AuthorAvatarURL)),
		MergedAt:            parseGHTime(ev.MergedAt),
		ClosedAt:            parseGHTime(ev.ClosedAt),
		PrCreatedAt:         parseGHTimeRequired(ev.CreatedAt),
		PrUpdatedAt:         parseGHTimeRequired(ev.UpdatedAt),
		Additions:           ev.Additions,
		Deletions:           ev.Deletions,
		ChangedFiles:        ev.ChangedFiles,
		HeadSha:             ev.HeadSHA,
		DetailedMergeStatus: ev.DetailedMergeStatus,
	})
	if err != nil {
		slog.Warn("vcs: upsert pr failed", "err", err)
		return
	}

	// Out-of-order guard for the link metadata. UpsertVCSPullRequest keeps the
	// newer persisted row on a stale redelivery, so `pr` may reflect a newer
	// event than this `ev`. Everything the link write derives below —
	// close_intent, reference_only, preserveCloseIntent — comes from `ev`, so
	// rewriting the link from a stale event would corrupt what the newer event
	// already set (e.g. a redelivered older "opened" event flipping a merged
	// PR's link back to reference_only, blocking auto-advance). If the persisted
	// row is strictly newer than this event, the newer event already linked and
	// published — stop here. (An event with no usable timestamp falls back to
	// now(), which is never strictly after the stored value, so it proceeds.)
	evUpdatedAt := parseGHTimeRequired(ev.UpdatedAt)
	if pr.PrUpdatedAt.Valid && evUpdatedAt.Valid && pr.PrUpdatedAt.Time.After(evUpdatedAt.Time) {
		return
	}

	workspaceID := uuidToString(conn.WorkspaceID)
	resp := vcsPullRequestToResponse(pr)

	// Auto-link to issues by identifiers in title/body/branch. Connecting a
	// a provider is the opt-in, so there is no separate per-workspace flag. The
	// issue-side machinery is shared with GitHub.
	linkedIssueIDs := make([]string, 0)
	idents := extractIdentifiers(ev.Title, ev.Body, ev.Branch)
	closingIdents := map[string]struct{}{}
	for _, c := range extractClosingIdentifiers(ev.Title, ev.Body) {
		closingIdents[c] = struct{}{}
	}
	// qualifyingIdents genuinely tie this PR to an issue: a title prefix, a
	// branch-name reference, or a body closing keyword. An identifier matched
	// ONLY by a bare body mention is reference_only — it links (so the PR shows
	// in history) but is hidden from the issue PR list and excluded from the
	// close aggregate, so a drive-by "Related MUL-1" neither looks like a
	// working PR nor blocks a genuine Closes sibling from advancing the issue.
	// Mirrors the GitHub path (MUL-3739); branch is deliberately excluded from
	// the closing-keyword scan there and here.
	qualifyingIdents := map[string]struct{}{}
	for _, id := range extractIdentifiers(ev.Title, ev.Branch) {
		qualifyingIdents[id] = struct{}{}
	}
	for c := range closingIdents {
		qualifyingIdents[c] = struct{}{}
	}
	// Freeze close_intent once the terminal merge/close event has arrived.
	preserveCloseIntent := !ev.Terminal() && (ev.State == "merged" || ev.State == "closed")
	prefix := h.getIssuePrefix(ctx, conn.WorkspaceID)
	reevalIssues := make([]db.Issue, 0, len(idents))
	for _, id := range idents {
		issue, ok := h.lookupIssueByIdentifier(ctx, conn.WorkspaceID, prefix, id)
		if !ok {
			continue
		}
		_, declared := closingIdents[id]
		closeIntent := declared && !preserveCloseIntent
		_, qualifies := qualifyingIdents[id]
		referenceOnly := !qualifies
		if err := h.Queries.LinkIssueToVCSPullRequest(ctx, db.LinkIssueToVCSPullRequestParams{
			IssueID:             issue.ID,
			PullRequestID:       pr.ID,
			CloseIntent:         closeIntent,
			ReferenceOnly:       referenceOnly,
			PreserveCloseIntent: preserveCloseIntent,
			LinkedByType:        strToText("system"),
			LinkedByID:          pgtype.UUID{},
		}); err != nil {
			slog.Warn("vcs: link failed", "err", err)
			continue
		}
		linkedIssueIDs = append(linkedIssueIDs, uuidToString(issue.ID))
		reevalIssues = append(reevalIssues, issue)
	}

	if ev.DetailedMergeStatus == "need_rebase" && ev.HeadSHA != "" {
		if _, err := h.Queries.CreateVCSPullRequestNotification(ctx, db.CreateVCSPullRequestNotificationParams{
			PullRequestID: pr.ID, HeadSha: ev.HeadSHA, Kind: "need_rebase",
		}); err == nil {
			issues, listErr := h.Queries.ListIssuesForVCSPullRequest(ctx, pr.ID)
			if listErr != nil {
				slog.Warn("vcs: list linked issues for need_rebase failed", "err", listErr)
			}
			for _, issue := range issues {
				h.createVCSSystemComment(ctx, issue, fmt.Sprintf(
					"GitLab merge request needs a rebase.\n\nMR: %s\nHead SHA: `%s`\nStatus: `need_rebase`",
					ev.HTMLURL, ev.HeadSHA), true)
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("vcs: record need_rebase notification failed", "err", err)
		}
	}

	if ev.State == "merged" || ev.State == "closed" {
		for _, issue := range reevalIssues {
			// A custom terminal status counts as terminal here. (MUL-6243)
			if s := issuestatus.Effective(ctx, h.Queries, issue.WorkspaceID, issue.Status); s == "done" || s == "cancelled" {
				continue
			}
			counts, err := h.Queries.GetIssueCombinedPullRequestCloseAggregate(ctx, issue.ID)
			if err != nil {
				slog.Warn("vcs: count linked pr states failed", "err", err, "issue_id", uuidToString(issue.ID))
				continue
			}
			if counts.OpenCount == 0 && counts.MergedWithCloseIntentCount > 0 {
				h.advanceIssueToDone(ctx, issue, workspaceID)
			}
		}
	}

	h.publish(protocol.EventPullRequestUpdated, workspaceID, "system", "", map[string]any{
		"pull_request":     resp,
		"linked_issue_ids": linkedIssueIDs,
	})
}

func (h *Handler) mirrorVCSReview(ctx context.Context, conn db.VcsConnection, provider vcs.ReviewProvider, ev vcs.ReviewEvent) {
	if ev.System || ev.Action != "create" || ev.ReviewerLogin == "" ||
		strings.EqualFold(ev.ReviewerLogin, conn.AccountLogin) {
		return
	}
	if ev.DiscussionID == "" {
		token, err := h.openVCSSecret(conn.AccessTokenEncrypted)
		if err != nil {
			slog.Warn("vcs: decrypt access token for review enrichment failed", "err", err)
			return
		}
		enriched, err := provider.EnrichReview(ctx, conn.InstanceUrl, token, ev)
		if err != nil {
			slog.Warn("vcs: enrich review discussion failed", "err", err)
			return
		}
		ev = enriched
	}
	if ev.DiscussionID == "" || ev.NoteID == "" || ev.Body == "" {
		return
	}
	pr, err := h.Queries.GetVCSPullRequestByExternalID(ctx, db.GetVCSPullRequestByExternalIDParams{
		ConnectionID: conn.ID, RepoOwner: ev.RepoOwner, RepoName: ev.RepoName, PrNumber: ev.Number,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("vcs: lookup review merge request failed", "err", err)
		}
		return
	}
	// A note for an older head is retained by GitLab, but must not start a run
	// against a different checkout. A fresh Note Hook carries last_commit.id.
	if ev.HeadSHA == "" || ev.HeadSHA != pr.HeadSha {
		slog.Warn("vcs: ignore review for stale merge request head", "event_head", ev.HeadSHA, "stored_head", pr.HeadSha)
		return
	}
	position := ev.Position
	if len(position) == 0 || string(position) == "null" {
		position = json.RawMessage(`{}`)
	}
	thread, err := h.Queries.CreateVCSReviewThread(ctx, db.CreateVCSReviewThreadParams{
		WorkspaceID: conn.WorkspaceID, ConnectionID: conn.ID, PullRequestID: pr.ID,
		Provider: conn.Provider, DiscussionID: ev.DiscussionID, NoteID: ev.NoteID,
		NoteUrl: ev.NoteURL, ReviewerLogin: ev.ReviewerLogin, ReviewerName: ev.ReviewerName,
		ReviewerAvatarUrl: ev.ReviewerAvatarURL, Body: ev.Body, HeadSha: ev.HeadSHA,
		Position: position, Resolvable: ev.Resolvable, Resolved: ev.Resolved, EventAction: ev.Action,
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("vcs: store review thread failed", "err", err)
		}
		return // duplicate delivery is deliberately silent
	}
	issues, err := h.Queries.ListIssuesForVCSPullRequest(ctx, pr.ID)
	if err != nil {
		slog.Warn("vcs: list linked issues for review failed", "err", err)
		return
	}
	for _, issue := range issues {
		content := fmt.Sprintf(
			"GitLab review discussion from @%s\n\n%s\n\nMR: %s\nDiscussion: `%s`\nReview ID: `%s`\nReview head SHA: `%s`\n\nAfter pushing the fix, use the pushed commit as the expected head: `multica issue review reply %s %s --body-file ./reply.md --expected-head-sha $(git rev-parse HEAD)`, then resolve with `multica issue review resolve %s %s --expected-head-sha $(git rev-parse HEAD)`.",
			ev.ReviewerLogin, ev.Body, ev.MRURL, ev.DiscussionID, uuidToString(thread.ID), ev.HeadSHA,
			uuidToString(issue.ID), uuidToString(thread.ID),
			uuidToString(issue.ID), uuidToString(thread.ID))
		h.createVCSSystemComment(ctx, issue, content, true)
	}
}

func (h *Handler) createVCSSystemComment(ctx context.Context, issue db.Issue, content string, trigger bool) {
	comment, err := h.Queries.CreateComment(ctx, db.CreateCommentParams{
		IssueID: issue.ID, WorkspaceID: issue.WorkspaceID, AuthorType: "system",
		AuthorID: pgtype.UUID{Valid: true}, Content: content, Type: "system",
		ParentID: pgtype.UUID{},
	})
	if err != nil {
		slog.Warn("vcs: create system comment failed", "err", err)
		return
	}
	h.publish(protocol.EventCommentCreated, uuidToString(issue.WorkspaceID), "system", "", map[string]any{
		"comment": commentToResponse(comment, nil, nil), "issue_title": issue.Title,
		"issue_assignee_type": textToPtr(issue.AssigneeType), "issue_assignee_id": uuidToPtr(issue.AssigneeID),
		"issue_status": issue.Status,
	})
	if trigger {
		// Route only to the linked issue's assignee. Passing the external review
		// body through generic mention parsing would let provider-controlled text
		// name arbitrary Multica agents. The normal assignee resolver and enqueue
		// pipeline still provide invocation gates, head-scoped dedup, coalescing,
		// and task attribution for this system principal.
		opts := commentTriggerComputeOptions{ExcludeTriggerCommentID: comment.ID}
		if assignee, ok := h.routeAssigneeFallback(ctx, issue, "system", "", opts); ok {
			h.enqueueCommentAgentTriggers(ctx, issue, comment.ID, []commentAgentTrigger{assignee})
		}
	}
}

func (h *Handler) mirrorVCSCIStatus(ctx context.Context, conn db.VcsConnection, ev vcs.CIStatusEvent) {
	if ev.SHA == "" || ev.State == "" {
		return
	}
	// Use the provider's own event timestamp so UpsertVCSCommitStatus's
	// monotonic guard has something real to compare — writing time.Now() here
	// made the guard always true, so an out-of-order redelivery could regress a
	// status. Falls back to now() only when the payload carried no timestamp.
	if err := h.Queries.UpsertVCSCommitStatus(ctx, db.UpsertVCSCommitStatusParams{
		ConnectionID: conn.ID,
		Sha:          ev.SHA,
		Context:      ev.Context,
		State:        ev.State,
		TargetUrl:    ptrToText(strPtrOrNil(ev.TargetURL)),
		Description:  ptrToText(strPtrOrNil(ev.Description)),
		UpdatedAt:    parseGHTimeRequired(ev.UpdatedAt),
	}); err != nil {
		slog.Warn("vcs: upsert commit status failed", "err", err)
		return
	}

	issueIDs, err := h.Queries.ListIssueIDsForVCSPRHead(ctx, db.ListIssueIDsForVCSPRHeadParams{
		ConnectionID: conn.ID,
		HeadSha:      ev.SHA,
	})
	if err != nil {
		slog.Warn("vcs: lookup issues for status failed", "err", err)
		return
	}
	workspaceID := uuidToString(conn.WorkspaceID)
	for _, issueID := range issueIDs {
		h.publish(protocol.EventPullRequestUpdated, workspaceID, "system", "", map[string]any{
			"issue_id": uuidToString(issueID),
		})
	}
}
