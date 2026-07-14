CREATE TABLE `match_replace_rules` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`name` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`part` text NOT NULL,
	`match` text DEFAULT '' NOT NULL,
	`replace` text DEFAULT '' NOT NULL,
	`is_regex` integer DEFAULT false NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `match_replace_domain_idx` ON `match_replace_rules` (`domain_id`);