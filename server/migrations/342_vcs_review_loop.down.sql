DROP TABLE IF EXISTS vcs_pull_request_notification;
DROP TABLE IF EXISTS vcs_review_action;
DROP TABLE IF EXISTS vcs_review_thread;
ALTER TABLE vcs_pull_request DROP COLUMN IF EXISTS detailed_merge_status;
