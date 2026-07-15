CREATE TABLE `asset_findings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`asset_id` integer NOT NULL,
	`finding_id` integer NOT NULL,
	FOREIGN KEY (`asset_id`) REFERENCES `assets`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`finding_id`) REFERENCES `findings`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `asset_findings_asset_idx` ON `asset_findings` (`asset_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `asset_findings_uq` ON `asset_findings` (`asset_id`,`finding_id`);--> statement-breakpoint
CREATE TABLE `assets` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`kind` text NOT NULL,
	`value` text NOT NULL,
	`ip` text,
	`port` integer,
	`asn` text,
	`asn_name` text,
	`cdn` text,
	`first_seen` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`last_seen` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `assets_domain_idx` ON `assets` (`domain_id`);--> statement-breakpoint
CREATE INDEX `assets_ip_idx` ON `assets` (`ip`);--> statement-breakpoint
CREATE UNIQUE INDEX `assets_domain_kind_value_uq` ON `assets` (`domain_id`,`kind`,`value`);