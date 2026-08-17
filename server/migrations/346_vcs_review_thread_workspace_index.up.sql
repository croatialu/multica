CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vcs_review_thread_workspace
    ON vcs_review_thread (workspace_id);
