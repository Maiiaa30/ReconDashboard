CREATE TABLE `assessment_executions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`step_id` integer NOT NULL,
	`job_id` integer NOT NULL,
	`target` text,
	`attempt` integer DEFAULT 1 NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`outcome` text DEFAULT 'pending' NOT NULL,
	`reason` text,
	`summary` text DEFAULT '[]' NOT NULL,
	`findings_produced` integer DEFAULT 0 NOT NULL,
	`high_findings` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`step_id`) REFERENCES `assessment_steps`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `assessment_executions_job_uq` ON `assessment_executions` (`job_id`);--> statement-breakpoint
CREATE INDEX `assessment_executions_step_idx` ON `assessment_executions` (`step_id`,`id`);--> statement-breakpoint
CREATE TABLE `assessment_run_findings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`run_id` integer NOT NULL,
	`finding_id` integer,
	`finding_key` text NOT NULL,
	`type` text NOT NULL,
	`title` text NOT NULL,
	`target` text,
	`score` integer,
	`severity` text,
	`status` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`run_id`) REFERENCES `assessment_runs`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`finding_id`) REFERENCES `findings`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `assessment_run_findings_key_uq` ON `assessment_run_findings` (`run_id`,`finding_key`);--> statement-breakpoint
CREATE INDEX `assessment_run_findings_run_idx` ON `assessment_run_findings` (`run_id`);--> statement-breakpoint
ALTER TABLE `report_snapshots` ADD `assessment_run_id` integer REFERENCES assessment_runs(id) ON DELETE set null;--> statement-breakpoint
CREATE INDEX `report_snapshot_run_idx` ON `report_snapshots` (`assessment_run_id`);
