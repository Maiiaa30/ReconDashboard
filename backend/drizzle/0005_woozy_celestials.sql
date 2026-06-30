ALTER TABLE `findings` ADD `dedupe_key` text;--> statement-breakpoint
CREATE INDEX `findings_dedupe_idx` ON `findings` (`domain_id`,`type`,`dedupe_key`);