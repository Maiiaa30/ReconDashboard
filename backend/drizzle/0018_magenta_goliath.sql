ALTER TABLE `asset_cves` ADD `alerted_at` integer;--> statement-breakpoint
-- Backfill: every row recorded before this column existed is treated as already
-- alerted / baselined (alerted_at = first_seen_at), so introducing the column
-- does not make the watch re-alert the entire historical CVE set on the next run.
UPDATE `asset_cves` SET `alerted_at` = `first_seen_at` WHERE `alerted_at` IS NULL;
