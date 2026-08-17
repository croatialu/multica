package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util/secretbox"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func withVCSBox(t *testing.T) *secretbox.Box {
	t.Helper()
	box, err := secretbox.New(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatalf("secretbox.New: %v", err)
	}
	prev := testHandler.VCSSecretBox
	testHandler.VCSSecretBox = box
	// The feature also requires the deployment-level switch; the box alone is
	// no longer sufficient. Enable it for the "configured" path tests.
	prevEnabled := testHandler.cfg.VCSIntegrationEnabled
	testHandler.cfg.VCSIntegrationEnabled = true
	t.Cleanup(func() {
		testHandler.VCSSecretBox = prev
		testHandler.cfg.VCSIntegrationEnabled = prevEnabled
	})
	return box
}

const vcsTestSecret = "vcs-webhook-secret"

func seedVCSConnection(t *testing.T, ctx context.Context, box *secretbox.Box, provider, instanceURL string) string {
	t.Helper()
	sealed, err := box.Seal([]byte(vcsTestSecret))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tokenSealed, _ := box.Seal([]byte("tok"))
	conn, err := testHandler.Queries.UpsertVCSConnection(ctx, db.UpsertVCSConnectionParams{
		WorkspaceID:            parseUUID(testWorkspaceID),
		Provider:               provider,
		InstanceUrl:            instanceURL,
		AccountLogin:           "acme",
		AccessTokenEncrypted:   base64.StdEncoding.EncodeToString(tokenSealed),
		WebhookSecretEncrypted: base64.StdEncoding.EncodeToString(sealed),
		ConnectedByID:          pgtype.UUID{},
	})
	if err != nil {
		t.Fatalf("UpsertVCSConnection: %v", err)
	}
	return uuidToString(conn.ID)
}

func cleanupVCS(ctx context.Context, issueID string) {
	testPool.Exec(ctx, `DELETE FROM vcs_review_action WHERE workspace_id = $1`, testWorkspaceID)
	testPool.Exec(ctx, `DELETE FROM vcs_review_thread WHERE workspace_id = $1`, testWorkspaceID)
	testPool.Exec(ctx, `DELETE FROM vcs_pull_request_notification n USING vcs_pull_request pr WHERE n.pull_request_id = pr.id AND pr.workspace_id = $1`, testWorkspaceID)
	testPool.Exec(ctx, `DELETE FROM issue_vcs_pull_request WHERE issue_id = $1`, issueID)
	testPool.Exec(ctx, `DELETE FROM vcs_commit_status cs USING vcs_connection c WHERE cs.connection_id = c.id AND c.workspace_id = $1`, testWorkspaceID)
	testPool.Exec(ctx, `DELETE FROM vcs_pull_request WHERE workspace_id = $1`, testWorkspaceID)
	testPool.Exec(ctx, `DELETE FROM vcs_connection WHERE workspace_id = $1`, testWorkspaceID)
	if issueID != "" {
		testPool.Exec(ctx, `DELETE FROM activity_log WHERE issue_id = $1`, issueID)
		testPool.Exec(ctx, `DELETE FROM issue WHERE id = $1`, issueID)
	}
}

func gitlabWebhook(t *testing.T, connID, event string, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitlab-Event": event, "X-Gitlab-Token": vcsTestSecret,
	}, raw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("%s: got %d: %s", event, w.Code, w.Body.String())
	}
	return w
}

func gitlabMRPayload(issue IssueResponse, head, updatedAt, detailedStatus string) map[string]any {
	return map[string]any{
		"object_kind": "merge_request",
		"user":        map[string]any{"username": "author"},
		"project":     map[string]any{"path_with_namespace": "acme/widget"},
		"object_attributes": map[string]any{
			"iid": 42, "title": "Fix " + issue.Identifier, "description": "",
			"state": "opened", "action": "update", "source_branch": "fix/review",
			"url":        "https://gitlab.test/acme/widget/-/merge_requests/42",
			"created_at": "2026-08-17T01:00:00Z", "updated_at": updatedAt,
			"last_commit": map[string]any{"id": head}, "detailed_merge_status": detailedStatus,
		},
	}
}

func gitlabNotePayload(noteID int, reviewer, head string) map[string]any {
	return map[string]any{
		"object_kind": "note",
		"user":        map[string]any{"name": "Reviewer", "username": reviewer},
		"project":     map[string]any{"path_with_namespace": "acme/widget"},
		"object_attributes": map[string]any{
			"id": noteID, "note": "Please cover the nil case", "noteable_type": "MergeRequest",
			"discussion_id": "discussion-1", "system": false, "action": "create",
			"url":        "https://gitlab.test/acme/widget/-/merge_requests/42#note_55",
			"resolvable": true, "resolved": false,
			"position": map[string]any{"head_sha": head, "new_path": "a.go", "new_line": 9},
		},
		"merge_request": map[string]any{
			"iid": 42, "url": "https://gitlab.test/acme/widget/-/merge_requests/42",
			"last_commit": map[string]any{"id": head},
		},
	}
}

func TestVCSWebhook_GitLabReviewAndNeedRebaseAreDeduplicated(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "gitlab", "https://gitlab.test")
	issue := newVCSIssue(t, "GitLab review follow-up")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })
	agentID := createHandlerTestAgent(t, "GitLab Review Resume Agent", nil)
	if _, err := testPool.Exec(ctx, `UPDATE issue SET assignee_type = 'agent', assignee_id = $2 WHERE id = $1`, issue.ID, agentID); err != nil {
		t.Fatalf("assign agent: %v", err)
	}

	gitlabWebhook(t, connID, "Merge Request Hook", gitlabMRPayload(issue, "head-1", "2026-08-17T01:01:00Z", "mergeable"))
	note := gitlabNotePayload(55, "human-reviewer", "head-1")
	gitlabWebhook(t, connID, "Note Hook", note)
	gitlabWebhook(t, connID, "Note Hook", note)

	count, err := testHandler.Queries.CountComments(ctx, db.CountCommentsParams{IssueID: parseUUID(issue.ID), WorkspaceID: parseUUID(testWorkspaceID)})
	if err != nil || count != 1 {
		t.Fatalf("review comments = %d, err=%v; want 1", count, err)
	}
	var tasks int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM agent_task_queue WHERE issue_id = $1 AND agent_id = $2 AND status IN ('queued','dispatched','running','waiting_local_directory','deferred')`, issue.ID, agentID).Scan(&tasks); err != nil || tasks != 1 {
		t.Fatalf("review-triggered tasks = %d, err=%v; want exactly 1", tasks, err)
	}
	var threads int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM vcs_review_thread WHERE workspace_id = $1`, testWorkspaceID).Scan(&threads); err != nil || threads != 1 {
		t.Fatalf("review threads = %d, err=%v; want 1", threads, err)
	}

	// Notes authored by the connected integration account and stale-head notes
	// are both ignored, preventing loops and wrong-checkout agent runs.
	gitlabWebhook(t, connID, "Note Hook", gitlabNotePayload(56, "acme", "head-1"))
	gitlabWebhook(t, connID, "Note Hook", gitlabNotePayload(57, "human-reviewer", "old-head"))
	count, _ = testHandler.Queries.CountComments(ctx, db.CountCommentsParams{IssueID: parseUUID(issue.ID), WorkspaceID: parseUUID(testWorkspaceID)})
	if count != 1 {
		t.Fatalf("ignored notes changed comment count to %d", count)
	}

	needRebase := gitlabMRPayload(issue, "head-1", "2026-08-17T01:02:00Z", "need_rebase")
	gitlabWebhook(t, connID, "Merge Request Hook", needRebase)
	gitlabWebhook(t, connID, "Merge Request Hook", needRebase)
	count, _ = testHandler.Queries.CountComments(ctx, db.CountCommentsParams{IssueID: parseUUID(issue.ID), WorkspaceID: parseUUID(testWorkspaceID)})
	if count != 2 {
		t.Fatalf("review + need_rebase comments = %d, want 2", count)
	}
}

func TestVCSReviewAction_ReplyThenResolveAfterPush(t *testing.T) {
	ctx := context.Background()
	var providerCalls []string
	gitlab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "tok" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		providerCalls = append(providerCalls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/merge_requests/42"):
			_, _ = w.Write([]byte(`{"sha":"head-2","state":"opened"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/discussions/discussion-1"):
			_, _ = w.Write([]byte(`{"id":"discussion-1","notes":[{"id":55,"resolvable":true,"resolved":false}]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/discussions/discussion-1/notes"):
			_, _ = w.Write([]byte(`{"id":99}`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/discussions/discussion-1"):
			_, _ = w.Write([]byte(`{"id":"discussion-1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gitlab.Close()

	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "gitlab", gitlab.URL)
	issue := newVCSIssue(t, "GitLab review action")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })
	gitlabWebhook(t, connID, "Merge Request Hook", gitlabMRPayload(issue, "head-1", "2026-08-17T02:01:00Z", "mergeable"))
	gitlabWebhook(t, connID, "Note Hook", gitlabNotePayload(55, "human-reviewer", "head-1"))
	// Simulate the agent's fix push and the following MR webhook. The review
	// thread remains anchored to head-1, while actions must prove head-2 is the
	// current provider and persisted MR head.
	gitlabWebhook(t, connID, "Merge Request Hook", gitlabMRPayload(issue, "head-2", "2026-08-17T02:02:00Z", "mergeable"))

	var reviewID string
	if err := testPool.QueryRow(ctx, `SELECT id FROM vcs_review_thread WHERE workspace_id = $1 AND note_id = '55'`, testWorkspaceID).Scan(&reviewID); err != nil {
		t.Fatalf("load review: %v", err)
	}
	agentID := createHandlerTestAgent(t, "GitLab Review Agent", nil)
	if _, err := testPool.Exec(ctx, `UPDATE issue SET assignee_type = 'agent', assignee_id = $2 WHERE id = $1`, issue.ID, agentID); err != nil {
		t.Fatalf("assign agent: %v", err)
	}
	taskID := createHandlerTestTaskForAgentOnIssue(t, agentID, issue.ID)

	act := func(requestID, action, head, body string) *httptest.ResponseRecorder {
		req := newRequest("POST", "/api/issues/"+issue.ID+"/reviews/"+reviewID+"/actions", map[string]any{
			"request_id": requestID, "action": action, "expected_head_sha": head, "body": body,
		})
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Task-ID", taskID)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", issue.ID)
		rctx.URLParams.Add("reviewId", reviewID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		testHandler.ActOnVCSReview(w, req)
		return w
	}
	memberReq := newRequest("POST", "/api/issues/"+issue.ID+"/reviews/"+reviewID+"/actions", map[string]any{
		"request_id": "00000000-0000-4000-8000-000000000000", "action": "reply",
		"expected_head_sha": "head-2", "body": "not authorized",
	})
	memberCtx := chi.NewRouteContext()
	memberCtx.URLParams.Add("id", issue.ID)
	memberCtx.URLParams.Add("reviewId", reviewID)
	memberReq = memberReq.WithContext(context.WithValue(memberReq.Context(), chi.RouteCtxKey, memberCtx))
	member := httptest.NewRecorder()
	testHandler.ActOnVCSReview(member, memberReq)
	if member.Code != http.StatusForbidden || len(providerCalls) != 0 {
		t.Fatalf("member action: status=%d calls=%v", member.Code, providerCalls)
	}

	stale := act("00000000-0000-4000-8000-000000000001", "reply", "head-1", "fixed")
	if stale.Code != http.StatusConflict || len(providerCalls) != 0 {
		t.Fatalf("stale action: status=%d calls=%v body=%s", stale.Code, providerCalls, stale.Body.String())
	}
	premature := act("00000000-0000-4000-8000-000000000004", "resolve", "head-2", "")
	if premature.Code != http.StatusConflict || len(providerCalls) != 2 {
		t.Fatalf("premature resolve: status=%d calls=%v body=%s", premature.Code, providerCalls, premature.Body.String())
	}
	reply := act("00000000-0000-4000-8000-000000000002", "reply", "head-2", "Fixed and tested.")
	if reply.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", reply.Code, reply.Body.String())
	}
	resolve := act("00000000-0000-4000-8000-000000000003", "resolve", "head-2", "")
	if resolve.Code != http.StatusOK {
		t.Fatalf("resolve: %d %s", resolve.Code, resolve.Body.String())
	}
	if len(providerCalls) != 8 {
		t.Fatalf("provider calls = %v, want 8", providerCalls)
	}

	var resolved bool
	var succeeded int
	if err := testPool.QueryRow(ctx, `SELECT resolved FROM vcs_review_thread WHERE id = $1`, reviewID).Scan(&resolved); err != nil || !resolved {
		t.Fatalf("resolved=%v err=%v", resolved, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM vcs_review_action WHERE review_thread_id = $1 AND status = 'succeeded'`, reviewID).Scan(&succeeded); err != nil || succeeded != 2 {
		t.Fatalf("successful audit actions=%d err=%v", succeeded, err)
	}
}

func newVCSIssue(t *testing.T, title string) IssueResponse {
	t.Helper()
	w := httptest.NewRecorder()
	req := newRequest("POST", "/api/issues?workspace_id="+testWorkspaceID, map[string]any{
		"title": title, "status": "in_progress",
	})
	testHandler.CreateIssue(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateIssue: %d %s", w.Code, w.Body.String())
	}
	var created IssueResponse
	json.NewDecoder(w.Body).Decode(&created)
	return created
}

func vcsWebhookReq(connID string, headers map[string]string, raw []byte) *http.Request {
	req := httptest.NewRequest("POST", "/api/webhooks/vcs/"+connID, bytes.NewReader(raw))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("connectionId", connID)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func giteaSig(raw []byte) string {
	mac := hmac.New(sha256.New, []byte(vcsTestSecret))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVCSWebhook_ForgejoMirrorsAndCloses(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	issue := newVCSIssue(t, "Forgejo PR auto-merge")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })

	raw, _ := json.Marshal(map[string]any{
		"action": "closed",
		"pull_request": map[string]any{
			"number": 7, "html_url": "https://forgejo.test/acme/widget/pulls/7",
			"title": "Fix login " + issue.Identifier, "body": "Closes " + issue.Identifier,
			"state": "closed", "merged": true,
			"merged_at": "2026-04-29T00:00:00Z", "closed_at": "2026-04-29T00:00:00Z",
			"created_at": "2026-04-28T00:00:00Z", "updated_at": "2026-04-29T00:00:00Z",
			"head": map[string]any{"ref": "fix/login", "sha": "abc"},
			"user": map[string]any{"username": "octo"},
		},
		"repository": map[string]any{"name": "widget", "owner": map[string]any{"username": "acme"}},
	})
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(raw),
	}, raw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d (%s)", w.Code, w.Body.String())
	}

	rows, err := testHandler.Queries.ListVCSPullRequestsByIssue(ctx, parseUUID(issue.ID))
	if err != nil {
		t.Fatalf("ListVCSPullRequestsByIssue: %v", err)
	}
	if len(rows) != 1 || rows[0].State != "merged" || rows[0].Provider != "forgejo" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	updated, _ := testHandler.Queries.GetIssue(ctx, parseUUID(issue.ID))
	if updated.Status != "done" {
		t.Errorf("expected issue done, got %q", updated.Status)
	}
}

// A bare body mention ("Related MUL-X", no closing keyword, not in title or
// branch) must link reference_only: excluded from the issue PR list and from
// the close gate, so it neither shows as a working PR nor blocks a genuine
// Closes sibling from advancing the issue. Mirrors the GitHub qualifying rule.
func TestVCSWebhook_ReferenceOnlyExcludedAndNonBlocking(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	issue := newVCSIssue(t, "Reference-only mention")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })

	// PR #7: OPEN, mentions the issue only in the body with no closing keyword,
	// generic title/branch → reference_only.
	refRaw, _ := json.Marshal(map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"number": 7, "html_url": "https://forgejo.test/acme/widget/pulls/7",
			"title": "Update docs", "body": "Related " + issue.Identifier,
			"state": "open", "merged": false,
			"created_at": "2026-04-28T00:00:00Z", "updated_at": "2026-04-28T00:00:00Z",
			"head": map[string]any{"ref": "docs", "sha": "ref7"},
			"user": map[string]any{"username": "octo"},
		},
		"repository": map[string]any{"name": "widget", "owner": map[string]any{"username": "acme"}},
	})
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(refRaw),
	}, refRaw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("ref PR: expected 202, got %d (%s)", w.Code, w.Body.String())
	}

	// The link exists but is reference_only, so it is hidden from the PR list.
	var referenceOnly bool
	if err := testPool.QueryRow(ctx,
		`SELECT reference_only FROM issue_vcs_pull_request WHERE issue_id = $1`,
		issue.ID).Scan(&referenceOnly); err != nil {
		t.Fatalf("select reference_only: %v", err)
	}
	if !referenceOnly {
		t.Fatalf("body-only mention should be reference_only")
	}
	if rows, err := testHandler.Queries.ListVCSPullRequestsByIssue(ctx, parseUUID(issue.ID)); err != nil {
		t.Fatalf("list: %v", err)
	} else if len(rows) != 0 {
		t.Fatalf("reference_only PR must be excluded from the list, got %d rows", len(rows))
	}

	// PR #8: MERGED with a title reference + Closes keyword → qualifying,
	// close_intent. The still-open reference_only PR #7 must NOT block advance.
	closeRaw, _ := json.Marshal(map[string]any{
		"action": "closed",
		"pull_request": map[string]any{
			"number": 8, "html_url": "https://forgejo.test/acme/widget/pulls/8",
			"title": "Fix " + issue.Identifier, "body": "Closes " + issue.Identifier,
			"state": "closed", "merged": true,
			"merged_at": "2026-04-29T00:00:00Z", "closed_at": "2026-04-29T00:00:00Z",
			"created_at": "2026-04-28T00:00:00Z", "updated_at": "2026-04-29T00:00:00Z",
			"head": map[string]any{"ref": "fix", "sha": "cls8"},
			"user": map[string]any{"username": "octo"},
		},
		"repository": map[string]any{"name": "widget", "owner": map[string]any{"username": "acme"}},
	})
	w = httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(closeRaw),
	}, closeRaw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("close PR: expected 202, got %d (%s)", w.Code, w.Body.String())
	}

	updated, _ := testHandler.Queries.GetIssue(ctx, parseUUID(issue.ID))
	if updated.Status != "done" {
		t.Errorf("issue should advance despite the open reference_only PR, got %q", updated.Status)
	}
}

// The close gate must span providers: an issue with an OPEN GitHub PR and a
// MERGED close-intent VCS PR must report open_count > 0, so neither webhook
// auto-advances it out from under the still-open GitHub work (and vice versa).
func TestCombinedCloseAggregateSpansProviders(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "gitlab", "https://gitlab.test")
	issue := newVCSIssue(t, "Cross-provider close gate")
	now := pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
	t.Cleanup(func() {
		testPool.Exec(ctx, `DELETE FROM issue_pull_request WHERE issue_id = $1`, issue.ID)
		testPool.Exec(ctx, `DELETE FROM github_pull_request WHERE workspace_id = $1`, testWorkspaceID)
		cleanupVCS(ctx, issue.ID)
	})

	// OPEN GitHub PR linked to the issue (installation_id carries no FK).
	ghPR, err := testHandler.Queries.UpsertGitHubPullRequest(ctx, db.UpsertGitHubPullRequestParams{
		WorkspaceID: parseUUID(testWorkspaceID), InstallationID: 987654,
		RepoOwner: "acme", RepoName: "gh", PrNumber: 3,
		Title: "WIP " + issue.Identifier, State: "open",
		HtmlUrl:     "https://github.com/acme/gh/pull/3",
		PrCreatedAt: now, PrUpdatedAt: now, HeadSha: "ghsha",
	})
	if err != nil {
		t.Fatalf("UpsertGitHubPullRequest: %v", err)
	}
	if err := testHandler.Queries.LinkIssueToPullRequest(ctx, db.LinkIssueToPullRequestParams{
		IssueID: parseUUID(issue.ID), PullRequestID: ghPR.ID, CloseIntent: false,
		ReferenceOnly: false, LinkedByType: strToText("system"),
	}); err != nil {
		t.Fatalf("LinkIssueToPullRequest: %v", err)
	}

	// MERGED close-intent VCS PR linked to the same issue.
	vcsPR, err := testHandler.Queries.UpsertVCSPullRequest(ctx, db.UpsertVCSPullRequestParams{
		WorkspaceID: parseUUID(testWorkspaceID), ConnectionID: parseUUID(connID),
		Provider: "gitlab", RepoOwner: "acme", RepoName: "gl", PrNumber: 4,
		Title: "Fix " + issue.Identifier, State: "merged",
		HtmlUrl:     "https://gitlab.test/acme/gl/-/merge_requests/4",
		PrCreatedAt: now, PrUpdatedAt: now, HeadSha: "glsha",
	})
	if err != nil {
		t.Fatalf("UpsertVCSPullRequest: %v", err)
	}
	if err := testHandler.Queries.LinkIssueToVCSPullRequest(ctx, db.LinkIssueToVCSPullRequestParams{
		IssueID: parseUUID(issue.ID), PullRequestID: vcsPR.ID, CloseIntent: true,
		ReferenceOnly: false, LinkedByType: strToText("system"),
	}); err != nil {
		t.Fatalf("LinkIssueToVCSPullRequest: %v", err)
	}

	counts, err := testHandler.Queries.GetIssueCombinedPullRequestCloseAggregate(ctx, parseUUID(issue.ID))
	if err != nil {
		t.Fatalf("GetIssueCombinedPullRequestCloseAggregate: %v", err)
	}
	if counts.OpenCount != 1 {
		t.Errorf("open_count = %d, want 1 (the open GitHub PR must be seen)", counts.OpenCount)
	}
	if counts.MergedWithCloseIntentCount != 1 {
		t.Errorf("merged_with_close_intent_count = %d, want 1 (the VCS MR)", counts.MergedWithCloseIntentCount)
	}
}

// DeleteIssue's VCS-link cleanup must honour the same workspace guard as the
// issue delete: passing a foreign issue_id with a mismatched workspace_id must
// be a complete no-op, not silently drop the victim tenant's link rows (#1661).
func TestDeleteIssue_VCSLinkCleanupIsWorkspaceScoped(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	issue := newVCSIssue(t, "Tenant-scoped delete")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })

	raw, _ := json.Marshal(map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"number": 7, "html_url": "https://forgejo.test/acme/widget/pulls/7",
			"title": "Fix " + issue.Identifier, "state": "open", "merged": false,
			"created_at": "2026-05-01T00:00:00Z", "updated_at": "2026-05-01T00:00:00Z",
			"head": map[string]any{"ref": "fix", "sha": "abc"},
			"user": map[string]any{"username": "octo"},
		},
		"repository": map[string]any{"name": "widget", "owner": map[string]any{"username": "acme"}},
	})
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(raw),
	}, raw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("seed PR: %d %s", w.Code, w.Body.String())
	}

	linkCount := func() int {
		var n int
		testPool.QueryRow(ctx, `SELECT count(*) FROM issue_vcs_pull_request WHERE issue_id = $1`, issue.ID).Scan(&n)
		return n
	}
	if linkCount() != 1 {
		t.Fatalf("expected 1 link after seed, got %d", linkCount())
	}

	// Mismatched workspace_id → complete no-op: issue and link both survive.
	wrongWS := parseUUID("11111111-1111-1111-1111-111111111111")
	if err := testHandler.Queries.DeleteIssue(ctx, db.DeleteIssueParams{ID: parseUUID(issue.ID), WorkspaceID: wrongWS}); err != nil {
		t.Fatalf("DeleteIssue(wrong ws): %v", err)
	}
	if _, err := testHandler.Queries.GetIssue(ctx, parseUUID(issue.ID)); err != nil {
		t.Errorf("issue must survive a mismatched-workspace delete: %v", err)
	}
	if linkCount() != 1 {
		t.Errorf("link rows must survive a mismatched-workspace delete, got %d", linkCount())
	}

	// Correct workspace_id → issue and its links both removed.
	if err := testHandler.Queries.DeleteIssue(ctx, db.DeleteIssueParams{ID: parseUUID(issue.ID), WorkspaceID: parseUUID(testWorkspaceID)}); err != nil {
		t.Fatalf("DeleteIssue(correct ws): %v", err)
	}
	if linkCount() != 0 {
		t.Errorf("link rows should be gone after correct delete, got %d", linkCount())
	}
}

// A redelivered older event must not rewrite the link metadata that a newer
// event already set. The PR-upsert monotonic guard protects the PR row; this
// covers the link (close_intent / reference_only).
func TestVCSWebhook_StaleEventDoesNotRewriteLink(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	issue := newVCSIssue(t, "Out-of-order link guard")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })

	fire := func(action, state string, merged bool, title, body, updatedAt string) {
		raw, _ := json.Marshal(map[string]any{
			"action": action,
			"pull_request": map[string]any{
				"number": 7, "html_url": "https://forgejo.test/acme/widget/pulls/7",
				"title": title, "body": body, "state": state, "merged": merged,
				"created_at": "2026-05-01T00:00:00Z", "updated_at": updatedAt,
				"merged_at": "2026-05-02T00:00:00Z",
				"head":      map[string]any{"ref": "wip", "sha": "abc"},
				"user":      map[string]any{"username": "octo"},
			},
			"repository": map[string]any{"name": "widget", "owner": map[string]any{"username": "acme"}},
		})
		w := httptest.NewRecorder()
		testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
			"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(raw),
		}, raw))
		if w.Code != http.StatusAccepted {
			t.Fatalf("%s event: %d %s", action, w.Code, w.Body.String())
		}
	}

	// Newer terminal event: merged with a qualifying Closes → close_intent, not reference_only.
	fire("closed", "closed", true, "Fix "+issue.Identifier, "Closes "+issue.Identifier, "2026-05-02T00:00:00Z")
	// Older redelivered "opened" event: bare body mention, generic title/branch.
	// Without the guard this rewrites the link to close_intent=false, reference_only=true.
	fire("opened", "open", false, "WIP", "touches "+issue.Identifier, "2026-05-01T00:00:00Z")

	var closeIntent, referenceOnly bool
	if err := testPool.QueryRow(ctx,
		`SELECT close_intent, reference_only FROM issue_vcs_pull_request WHERE issue_id = $1`,
		issue.ID).Scan(&closeIntent, &referenceOnly); err != nil {
		t.Fatalf("select link: %v", err)
	}
	if !closeIntent || referenceOnly {
		t.Errorf("stale event rewrote link: close_intent=%v reference_only=%v, want true/false", closeIntent, referenceOnly)
	}
	// The PR row also stayed at the newer merged state.
	rows, _ := testHandler.Queries.ListVCSPullRequestsByIssue(ctx, parseUUID(issue.ID))
	if len(rows) != 1 || rows[0].State != "merged" {
		t.Errorf("PR row regressed: %+v", rows)
	}
}

func TestVCSWebhook_GitlabMergeRequest(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "gitlab", "https://gitlab.test")
	issue := newVCSIssue(t, "GitLab MR test")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })

	raw, _ := json.Marshal(map[string]any{
		"object_kind": "merge_request",
		"user":        map[string]any{"username": "alice"},
		"project":     map[string]any{"path_with_namespace": "acme/widget"},
		"object_attributes": map[string]any{
			"iid": 42, "title": "Add " + issue.Identifier, "description": "Closes " + issue.Identifier,
			"state": "merged", "action": "merge", "source_branch": "feat",
			"url":         "https://gitlab.test/acme/widget/-/merge_requests/42",
			"last_commit": map[string]any{"id": "deadbeef"},
		},
	})
	// GitLab authenticates by plaintext X-Gitlab-Token, not HMAC.
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitlab-Event": "Merge Request Hook", "X-Gitlab-Token": vcsTestSecret,
	}, raw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d (%s)", w.Code, w.Body.String())
	}

	rows, err := testHandler.Queries.ListVCSPullRequestsByIssue(ctx, parseUUID(issue.ID))
	if err != nil {
		t.Fatalf("ListVCSPullRequestsByIssue: %v", err)
	}
	if len(rows) != 1 || rows[0].Provider != "gitlab" || rows[0].RepoOwner != "acme" || rows[0].PrNumber != 42 {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if rows[0].State != "merged" {
		t.Errorf("expected merged, got %q", rows[0].State)
	}
	updated, _ := testHandler.Queries.GetIssue(ctx, parseUUID(issue.ID))
	if updated.Status != "done" {
		t.Errorf("expected issue done, got %q", updated.Status)
	}
}

func TestVCSWebhook_CommitStatusMirrors(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	issue := newVCSIssue(t, "Forgejo CI status")
	t.Cleanup(func() { cleanupVCS(ctx, issue.ID) })

	prRaw, _ := json.Marshal(map[string]any{
		"action": "opened",
		"pull_request": map[string]any{
			"number": 11, "html_url": "https://forgejo.test/acme/widget/pulls/11",
			"title": issue.Identifier + " feature", "state": "open",
			"created_at": "2026-04-28T00:00:00Z", "updated_at": "2026-04-28T00:00:00Z",
			"head": map[string]any{"ref": "feat", "sha": "deadbeef"},
			"user": map[string]any{"username": "octo"},
		},
		"repository": map[string]any{"name": "widget", "owner": map[string]any{"username": "acme"}},
	})
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(prRaw),
	}, prRaw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("pr: expected 202, got %d", w.Code)
	}

	stRaw, _ := json.Marshal(map[string]any{"sha": "deadbeef", "context": "ci/woodpecker", "state": "success"})
	w = httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "status", "X-Gitea-Signature": giteaSig(stRaw),
	}, stRaw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status: expected 202, got %d", w.Code)
	}

	rows, _ := testHandler.Queries.ListVCSPullRequestsByIssue(ctx, parseUUID(issue.ID))
	if len(rows) != 1 || rows[0].ChecksTotal != 1 || rows[0].ChecksPassed != 1 {
		t.Fatalf("expected 1 passed check, got %+v", rows)
	}
}

func TestVCSWebhook_BadSignature(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	t.Cleanup(func() { cleanupVCS(ctx, "") })

	raw := []byte(`{"action":"opened","pull_request":{"number":1}}`)
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": "00",
	}, raw))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestVCSWebhook_UnknownConnection(t *testing.T) {
	withVCSBox(t)
	req := vcsWebhookReq("00000000-0000-0000-0000-000000000000", map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": "00",
	}, []byte(`{}`))
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestVCSWebhook_DisabledDeploymentReturns404 verifies the deployment-level
// switch is enforced server-side: with the integration off (the managed-cloud
// posture), even a valid, correctly-signed delivery to a real connection is
// rejected with a bare 404, so the feature is never processed and reveals
// nothing about config. The availability gate short-circuits before signature
// verification.
func TestVCSWebhook_DisabledDeploymentReturns404(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t) // sets the box AND enables the switch
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	t.Cleanup(func() { cleanupVCS(ctx, "") })

	// Now flip the deployment switch off (withVCSBox's cleanup restores it).
	testHandler.cfg.VCSIntegrationEnabled = false

	raw := []byte(`{"action":"opened","pull_request":{"number":1}}`)
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(raw),
	}, raw))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when integration disabled, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestVCSWebhook_MalformedTolerated(t *testing.T) {
	ctx := context.Background()
	box := withVCSBox(t)
	connID := seedVCSConnection(t, ctx, box, "forgejo", "https://forgejo.test")
	t.Cleanup(func() { cleanupVCS(ctx, "") })

	raw := []byte(`{"action":"opened","pull_request":"not-an-object"}`)
	w := httptest.NewRecorder()
	testHandler.HandleVCSWebhook(w, vcsWebhookReq(connID, map[string]string{
		"X-Gitea-Event": "pull_request", "X-Gitea-Signature": giteaSig(raw),
	}, raw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d (%s)", w.Code, w.Body.String())
	}
	var count int
	testPool.QueryRow(ctx, `SELECT count(*) FROM vcs_pull_request WHERE workspace_id = $1`, testWorkspaceID).Scan(&count)
	if count != 0 {
		t.Errorf("expected no PR rows, got %d", count)
	}
}
