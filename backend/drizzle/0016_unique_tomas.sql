CREATE TABLE `captured_requests` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`method` text NOT NULL,
	`url` text NOT NULL,
	`host` text NOT NULL,
	`headers` text,
	`body` text,
	`source` text DEFAULT 'extension' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `captured_domain_idx` ON `captured_requests` (`domain_id`);--> statement-breakpoint
CREATE INDEX `captured_created_idx` ON `captured_requests` (`created_at`);