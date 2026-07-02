CREATE TABLE `asset_cves` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`ip` text NOT NULL,
	`cve_id` text NOT NULL,
	`cvss` real,
	`kev` integer DEFAULT false NOT NULL,
	`first_seen_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE INDEX `asset_cve_asset_idx` ON `asset_cves` (`domain_id`,`ip`);--> statement-breakpoint
CREATE UNIQUE INDEX `asset_cve_uq` ON `asset_cves` (`domain_id`,`ip`,`cve_id`);