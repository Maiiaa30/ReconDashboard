CREATE TABLE `asset_snapshots` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`ip` text NOT NULL,
	`ports` text DEFAULT '[]' NOT NULL,
	`tech` text DEFAULT '[]' NOT NULL,
	`up` integer DEFAULT false NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `asset_snapshots_domain_idx` ON `asset_snapshots` (`domain_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `asset_snapshots_domain_ip_uq` ON `asset_snapshots` (`domain_id`,`ip`);