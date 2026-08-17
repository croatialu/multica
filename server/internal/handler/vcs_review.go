package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/integrations/vcs"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type vcsReviewActionRequest struct {
	RequestID       string `json:"request_id"`
	Action          string `json:"action"`
	ExpectedHeadSHA string `json:"expected_head_sha"`
	Body            string `json:"body"`
}

// ActOnVCSReview performs a provider-side reply or resolution using stable
// review identifiers. The current issue assignment and task are authorization
// inputs, not merely attribution: a member token or an unrelated agent task
// cannot mutate an external review discussion.
func (h *Handler) ActOnVCSReview(w http.ResponseWriter, r *http.Request) {
	issue, ok := h.loadIssueForUser(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	userID := requestUserID(r)
	actorType, actorID := h.resolveActor(r, userID, uuidToString(issue.WorkspaceID))
	if actorType != "agent" || actorID == "" || !issue.AssigneeType.Valid ||
		issue.AssigneeType.String != "agent" || uuidToString(issue.AssigneeID) != actorID {
		writeError(w, http.StatusForbidden, "review actions require the issue's assigned agent")
		return
	}
	taskID := r.Header.Get("X-Task-ID")
	taskUUID, err := util.ParseUUID(taskID)
	if err != nil {
		writeError(w, http.StatusForbidden, "review actions require a valid current task")
		return
	}
	task, err := h.Queries.GetAgentTask(r.Context(), taskUUID)
	if err != nil || !task.IssueID.Valid || uuidToString(task.IssueID) != uuidToString(issue.ID) ||
		uuidToString(task.AgentID) != actorID || task.Status != "running" {
		writeError(w, http.StatusForbidden, "review action task does not match the running issue assignment")
		return
	}

	var req vcsReviewActionRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid review action body")
		return
	}
	requestUUID, err := util.ParseUUID(req.RequestID)
	if err != nil || req.ExpectedHeadSHA == "" || (req.Action != "reply" && req.Action != "resolve") {
		writeError(w, http.StatusBadRequest, "request_id, expected_head_sha, and an explicit reply or resolve action are required")
		return
	}
	req.Body = strings.TrimSpace(req.Body)
	if (req.Action == "reply" && req.Body == "") || (req.Action == "resolve" && req.Body != "") {
		writeError(w, http.StatusBadRequest, "reply requires body; resolve does not accept body")
		return
	}
	reviewUUID, err := util.ParseUUID(chi.URLParam(r, "reviewId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "review not found")
		return
	}
	thread, err := h.Queries.GetVCSReviewThreadForIssue(r.Context(), db.GetVCSReviewThreadForIssueParams{
		ID: reviewUUID, IssueID: issue.ID,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "review not found")
		return
	}
	pr, err := h.Queries.GetVCSPullRequest(r.Context(), thread.PullRequestID)
	if err != nil || (pr.State != "open" && pr.State != "draft") || pr.HeadSha != req.ExpectedHeadSHA {
		writeError(w, http.StatusConflict, "merge request head changed or is no longer open")
		return
	}
	conn, err := h.Queries.GetVCSConnectionByID(r.Context(), thread.ConnectionID)
	if err != nil || conn.WorkspaceID != issue.WorkspaceID {
		writeError(w, http.StatusNotFound, "review connection not found")
		return
	}
	provider, exists := vcs.For(conn.Provider)
	reviewProvider, supported := provider.(vcs.ReviewProvider)
	if !exists || !supported {
		writeError(w, http.StatusConflict, "provider does not support review actions")
		return
	}

	action, err := h.Queries.CreateVCSReviewAction(r.Context(), db.CreateVCSReviewActionParams{
		RequestID: requestUUID, WorkspaceID: issue.WorkspaceID, IssueID: issue.ID,
		ReviewThreadID: thread.ID, AgentID: issue.AssigneeID, TaskID: taskUUID,
		Action: req.Action, ExpectedHeadSha: req.ExpectedHeadSHA, Body: req.Body,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		action, err = h.Queries.GetVCSReviewAction(r.Context(), requestUUID)
		if err == nil && action.IssueID == issue.ID && action.ReviewThreadID == thread.ID &&
			action.Action == req.Action && action.ExpectedHeadSha == req.ExpectedHeadSHA && action.Body == req.Body {
			writeJSON(w, http.StatusOK, action)
			return
		}
		writeError(w, http.StatusConflict, "request_id was already used for another review action")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not record review action")
		return
	}

	fail := func(status int, message string, cause error) {
		detail := message
		if cause != nil {
			detail = cause.Error()
		}
		completed, updateErr := h.Queries.CompleteVCSReviewAction(r.Context(), db.CompleteVCSReviewActionParams{
			RequestID: requestUUID, Status: "failed", ExternalNoteID: "", Error: detail,
		})
		if updateErr == nil {
			writeJSON(w, status, completed)
			return
		}
		writeError(w, status, message)
	}
	token, err := h.openVCSSecret(conn.AccessTokenEncrypted)
	if err != nil {
		fail(http.StatusInternalServerError, "access token unavailable", err)
		return
	}
	target := vcs.ReviewTarget{
		ProjectPath: strings.Trim(pr.RepoOwner+"/"+pr.RepoName, "/"), Number: pr.PrNumber,
		DiscussionID: thread.DiscussionID, NoteID: thread.NoteID, ExpectedHeadSHA: req.ExpectedHeadSHA,
	}
	state, err := reviewProvider.ValidateReview(r.Context(), conn.InstanceUrl, token, target)
	if err != nil {
		fail(http.StatusConflict, "review target validation failed", err)
		return
	}
	if req.Action == "resolve" {
		if !state.Resolvable {
			fail(http.StatusConflict, "discussion is not resolvable", nil)
			return
		}
		replied, replyErr := h.Queries.HasSuccessfulVCSReviewReply(r.Context(), db.HasSuccessfulVCSReviewReplyParams{
			ReviewThreadID: thread.ID, ExpectedHeadSha: req.ExpectedHeadSHA,
		})
		if replyErr != nil || !replied {
			fail(http.StatusConflict, "reply successfully on this head before resolving", replyErr)
			return
		}
		if !state.Resolved {
			if err := reviewProvider.ResolveReview(r.Context(), conn.InstanceUrl, token, target); err != nil {
				fail(http.StatusBadGateway, "provider rejected review resolution", err)
				return
			}
		}
		_ = h.Queries.MarkVCSReviewThreadResolved(r.Context(), thread.ID)
	} else {
		externalNoteID, replyErr := reviewProvider.ReplyReview(r.Context(), conn.InstanceUrl, token, target, req.Body)
		if replyErr != nil {
			fail(http.StatusBadGateway, "provider rejected review reply", replyErr)
			return
		}
		action, err = h.Queries.CompleteVCSReviewAction(r.Context(), db.CompleteVCSReviewActionParams{
			RequestID: requestUUID, Status: "succeeded", ExternalNoteID: externalNoteID, Error: "",
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "provider replied but audit update failed")
			return
		}
		writeJSON(w, http.StatusOK, action)
		return
	}
	action, err = h.Queries.CompleteVCSReviewAction(r.Context(), db.CompleteVCSReviewActionParams{
		RequestID: requestUUID, Status: "succeeded", ExternalNoteID: "", Error: "",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "provider resolved discussion but audit update failed")
		return
	}
	writeJSON(w, http.StatusOK, action)
}
