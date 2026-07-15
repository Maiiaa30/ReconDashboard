CREATE TABLE `identities` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`name` text NOT NULL,
	`headers` text DEFAULT '{}' NOT NULL,
	`is_anon` integer DEFAULT false NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `identities_domain_idx` ON `identities` (`domain_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `identities_domain_name_uq` ON `identities` (`domain_id`,`name`);--> statement-breakpoint
ALTER TABLE `replay_history` ADD `identity_id` integer REFERENCES identities(id);