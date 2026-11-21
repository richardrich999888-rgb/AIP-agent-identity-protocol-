CREATE TABLE `workspace_audit` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`record` text NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`at` text NOT NULL,
	`detail` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `workspace_changes` (
	`tenant` text NOT NULL,
	`kind` text NOT NULL,
	`id` text NOT NULL,
	`version` integer NOT NULL,
	`payload` text NOT NULL,
	`modified` text NOT NULL,
	PRIMARY KEY(`tenant`, `kind`, `id`)
);
--> statement-breakpoint
CREATE TABLE `demo_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant` text NOT NULL,
	`role` text NOT NULL,
	`expires` integer NOT NULL
);
