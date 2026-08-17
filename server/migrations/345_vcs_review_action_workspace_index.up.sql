CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vcs_review_action_workspace
    ON vcs_review_action (workspace_id);
