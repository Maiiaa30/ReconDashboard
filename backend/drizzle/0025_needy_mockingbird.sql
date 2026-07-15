ALTER TABLE `findings` ADD `severity` text;--> statement-breakpoint
ALTER TABLE `findings` ADD `host` text;--> statement-breakpoint
ALTER TABLE `findings` ADD `ip` text;--> statement-breakpoint
ALTER TABLE `findings` ADD `url` text;--> statement-breakpoint
ALTER TABLE `findings` ADD `job_id` integer REFERENCES jobs(id);--> statement-breakpoint
CREATE INDEX `findings_status_idx` ON `findings` (`status`);--> statement-breakpoint
CREATE INDEX `findings_type_idx` ON `findings` (`type`);