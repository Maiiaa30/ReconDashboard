ALTER TABLE `domains` ADD `monitor_interval_hours` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `domains` ADD `last_monitored_at` integer;