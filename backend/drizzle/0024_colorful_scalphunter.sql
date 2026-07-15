CREATE TABLE `url_corpus` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`domain_id` integer,
	`url` text NOT NULL,
	`host` text,
	`source` text NOT NULL,
	`first_seen` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `url_corpus_domain_idx` ON `url_corpus` (`domain_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `url_corpus_domain_url_uq` ON `url_corpus` (`domain_id`,`url`);