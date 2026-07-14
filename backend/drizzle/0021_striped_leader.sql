ALTER TABLE `subdomains` ADD `login_hint` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `last_dashboard_viewed_at` integer;