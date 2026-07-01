CREATE TABLE `audit_log` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`ts` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`domain_id` integer,
	`target` text,
	`mode` text,
	`job_id` integer,
	`detail` text
);
--> statement-breakpoint
CREATE INDEX `audit_ts_idx` ON `audit_log` (`ts`);--> statement-breakpoint
CREATE INDEX `audit_domain_idx` ON `audit_log` (`domain_id`);--> statement-breakpoint
ALTER TABLE `domains` ADD `scope_config` text;--> statement-breakpoint
ALTER TABLE `domains` ADD `authorized_from` integer;--> statement-breakpoint
ALTER TABLE `domains` ADD `authorized_until` integer;