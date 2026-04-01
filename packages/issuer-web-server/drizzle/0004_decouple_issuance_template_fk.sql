CREATE TABLE `__new_issuance` (
	`id` text PRIMARY KEY NOT NULL,
	`owner_user_id` text NOT NULL,
	`template_id` text NOT NULL,
	`credential_configuration_id` text NOT NULL,
	`vct` text NOT NULL,
	`claims_json` text NOT NULL,
	`state` text NOT NULL,
	`offer_uri` text NOT NULL,
	`pre_authorized_code` text NOT NULL,
	`access_token` text,
	`credential` text,
	`status_list_id` text NOT NULL,
	`status_list_index` integer NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`owner_user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`status_list_id`) REFERENCES `status_list`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
INSERT INTO `__new_issuance`(
	`id`,
	`owner_user_id`,
	`template_id`,
	`credential_configuration_id`,
	`vct`,
	`claims_json`,
	`state`,
	`offer_uri`,
	`pre_authorized_code`,
	`access_token`,
	`credential`,
	`status_list_id`,
	`status_list_index`,
	`created_at`,
	`updated_at`
) SELECT
	`id`,
	`owner_user_id`,
	`template_id`,
	`credential_configuration_id`,
	`vct`,
	`claims_json`,
	`state`,
	`offer_uri`,
	`pre_authorized_code`,
	`access_token`,
	`credential`,
	`status_list_id`,
	`status_list_index`,
	`created_at`,
	`updated_at`
FROM `issuance`;
--> statement-breakpoint
DROP TABLE `issuance`;
--> statement-breakpoint
ALTER TABLE `__new_issuance` RENAME TO `issuance`;
--> statement-breakpoint
CREATE UNIQUE INDEX `issuance_pre_authorized_code_unique` ON `issuance` (`pre_authorized_code`);
--> statement-breakpoint
CREATE UNIQUE INDEX `issuance_access_token_unique` ON `issuance` (`access_token`);
--> statement-breakpoint
CREATE INDEX `idx_issuance_owner` ON `issuance` (`owner_user_id`);
--> statement-breakpoint
CREATE INDEX `idx_issuance_template` ON `issuance` (`template_id`);
