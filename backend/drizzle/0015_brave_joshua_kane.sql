CREATE TABLE `report_snapshots` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`host` text NOT NULL,
	`label` text,
	`content_md` text NOT NULL,
	`content_html` text NOT NULL,
	`meta` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `report_snapshot_domain_idx` ON `report_snapshots` (`domain_id`);