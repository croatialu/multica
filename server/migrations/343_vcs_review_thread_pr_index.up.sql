CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vcs_review_thread_pull_request
    ON vcs_review_thread (pull_request_id);
