-- GitLab review discussions are stored independently of comments. The stable
-- provider identifiers make webhook delivery and outbound actions auditable
-- without scraping system-comment prose. These tables intentionally have no
-- foreign keys; cleanup is handled by the existing explicit delete queries.
ALTER TABLE vcs_pull_request
    ADD COLUMN detailed_merge_status TEXT NOT NULL DEFAULT '';

CREATE TABLE vcs_review_thread (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    connection_id UUID NOT NULL,
    pull_request_id UUID NOT NULL,
    provider TEXT NOT NULL,
    discussion_id TEXT NOT NULL,
    note_id TEXT NOT NULL,
    note_url TEXT NOT NULL DEFAULT '',
    reviewer_login TEXT NOT NULL,
    reviewer_name TEXT NOT NULL DEFAULT '',
    reviewer_avatar_url TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    position JSONB NOT NULL DEFAULT '{}'::jsonb,
    resolvable BOOLEAN NOT NULL DEFAULT FALSE,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    event_action TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (connection_id, pull_request_id, note_id)
);

CREATE TABLE vcs_review_action (
    request_id UUID PRIMARY KEY,
    workspace_id UUID NOT NULL,
    issue_id UUID NOT NULL,
    review_thread_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    task_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('reply', 'resolve')),
    expected_head_sha TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed')),
    external_note_id TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vcs_pull_request_notification (
    pull_request_id UUID NOT NULL,
    head_sha TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('need_rebase')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pull_request_id, head_sha, kind)
);
