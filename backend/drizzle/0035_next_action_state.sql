CREATE TABLE `next_action_state` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer NOT NULL,
	`action_key` text NOT NULL,
	`state` text NOT NULL,
	`snapshot` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `next_action_state_domain_key_uq` ON `next_action_state` (`domain_id`,`action_key`);--> statement-breakpoint
CREATE INDEX `next_action_state_domain_idx` ON `next_action_state` (`domain_id`,`updated_at`);
