ALTER TABLE "analyses" ADD COLUMN "malware_family" varchar(100) DEFAULT 'Benign';--> statement-breakpoint
ALTER TABLE "analyses" ADD COLUMN "confidence" real DEFAULT 0.95;--> statement-breakpoint
ALTER TABLE "analyses" ADD COLUMN "family_probabilities" jsonb;--> statement-breakpoint
ALTER TABLE "analyses" ADD COLUMN "shap_explanation" jsonb;--> statement-breakpoint
ALTER TABLE "analyses" ADD COLUMN "feature_vector" jsonb;