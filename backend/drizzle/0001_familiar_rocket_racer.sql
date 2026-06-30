CREATE INDEX `findings_domain_idx` ON `findings` (`domain_id`);--> statement-breakpoint
CREATE INDEX `findings_score_idx` ON `findings` (`score`,`created_at`);--> statement-breakpoint
CREATE INDEX `jobs_status_id_idx` ON `jobs` (`status`,`id`);