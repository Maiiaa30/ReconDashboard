CREATE TABLE `assessment_runs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer NOT NULL,
	`profile` text NOT NULL,
	`name` text NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`created_by` text NOT NULL,
	`confirm_active` integer DEFAULT false NOT NULL,
	`current_phase` integer DEFAULT 0 NOT NULL,
	`total_phases` integer DEFAULT 1 NOT NULL,
	`started_at` integer,
	`completed_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `assessment_runs_domain_idx` ON `assessment_runs` (`domain_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `assessment_runs_status_idx` ON `assessment_runs` (`status`);--> statement-breakpoint
CREATE TABLE `assessment_steps` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`run_id` integer NOT NULL,
	`key` text NOT NULL,
	`label` text NOT NULL,
	`phase` integer NOT NULL,
	`position` integer NOT NULL,
	`action` text NOT NULL,
	`target_strategy` text DEFAULT 'domain' NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`jobs` text DEFAULT '[]' NOT NULL,
	`error` text,
	`started_at` integer,
	`completed_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`run_id`) REFERENCES `assessment_runs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `assessment_steps_run_key_uq` ON `assessment_steps` (`run_id`,`key`);--> statement-breakpoint
CREATE INDEX `assessment_steps_run_phase_idx` ON `assessment_steps` (`run_id`,`phase`,`position`);
