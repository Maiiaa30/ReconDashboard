ALTER TABLE `findings` ADD `last_seen_at` integer;--> statement-breakpoint
ALTER TABLE `jobs` ADD `domain_id` integer;--> statement-breakpoint
ALTER TABLE `jobs` ADD `attempts` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
CREATE INDEX `jobs_domain_type_idx` ON `jobs` (`domain_id`,`type`,`status`);--> statement-breakpoint
UPDATE `findings` SET `last_seen_at` = `created_at` WHERE `last_seen_at` IS NULL;