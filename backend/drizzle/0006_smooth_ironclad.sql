ALTER TABLE `findings` ADD `status` text DEFAULT 'open' NOT NULL;--> statement-breakpoint
ALTER TABLE `findings` ADD `note` text;