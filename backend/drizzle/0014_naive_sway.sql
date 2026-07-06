CREATE TABLE `skill_step_state` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer NOT NULL,
	`skill_id` text NOT NULL,
	`step_key` text NOT NULL,
	`state` text NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `skill_step_uq` ON `skill_step_state` (`domain_id`,`skill_id`,`step_key`);