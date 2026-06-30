ALTER TABLE `domains` ADD `profile` text;--> statement-breakpoint
ALTER TABLE `subdomains` ADD `ip_address` text;--> statement-breakpoint
ALTER TABLE `subdomains` ADD `http_status` integer;--> statement-breakpoint
ALTER TABLE `subdomains` ADD `title` text;--> statement-breakpoint
ALTER TABLE `subdomains` ADD `server` text;--> statement-breakpoint
ALTER TABLE `subdomains` ADD `scheme` text;--> statement-breakpoint
ALTER TABLE `subdomains` ADD `probed_at` integer;