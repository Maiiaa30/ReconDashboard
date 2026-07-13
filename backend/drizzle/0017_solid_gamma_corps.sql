CREATE TABLE `replay_history` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`method` text NOT NULL,
	`url` text NOT NULL,
	`req_headers` text,
	`req_body` text,
	`status` integer,
	`status_text` text,
	`time_ms` integer,
	`resp_bytes` integer,
	`resp_headers` text,
	`resp_body` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `replay_history_domain_idx` ON `replay_history` (`domain_id`);