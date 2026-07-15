CREATE TABLE `finding_links` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`from_id` integer NOT NULL,
	`to_id` integer NOT NULL,
	`kind` text NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`from_id`) REFERENCES `findings`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`to_id`) REFERENCES `findings`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `finding_links_to_idx` ON `finding_links` (`to_id`);--> statement-breakpoint
CREATE INDEX `finding_links_from_idx` ON `finding_links` (`from_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `finding_links_uq` ON `finding_links` (`from_id`,`to_id`,`kind`);