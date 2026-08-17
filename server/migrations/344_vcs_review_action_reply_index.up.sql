CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vcs_review_action_successful_reply
    ON vcs_review_action (review_thread_id, expected_head_sha)
    WHERE action = 'reply' AND status = 'succeeded';
