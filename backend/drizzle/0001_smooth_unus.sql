CREATE TABLE "analyses" (
	"id" serial PRIMARY KEY NOT NULL,
	"user_id" integer NOT NULL,
	"filename" varchar(500) NOT NULL,
	"original_filename" varchar(500) NOT NULL,
	"file_path" text NOT NULL,
	"file_size" integer NOT NULL,
	"md5" varchar(255) NOT NULL,
	"sha1" varchar(255) NOT NULL,
	"sha256" varchar(255) NOT NULL,
	"compile_time" timestamp,
	"entry_point" varchar(255),
	"image_base" varchar(255),
	"subsystem" varchar(255),
	"machine_type" varchar(255),
	"number_of_sections" integer,
	"entropy" real,
	"is_packed" boolean DEFAULT false,
	"is_suspicious" boolean DEFAULT false,
	"suspicious_score" integer DEFAULT 0,
	"analysis_status" varchar(50) DEFAULT 'completed',
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "imports" (
	"id" serial PRIMARY KEY NOT NULL,
	"analysis_id" integer NOT NULL,
	"dll_name" varchar(255) NOT NULL,
	"function_name" varchar(255) NOT NULL,
	"is_suspicious" integer DEFAULT 0
);
--> statement-breakpoint
CREATE TABLE "sections" (
	"id" serial PRIMARY KEY NOT NULL,
	"analysis_id" integer NOT NULL,
	"name" varchar(100) NOT NULL,
	"virtual_size" integer,
	"raw_size" integer,
	"entropy" real,
	"characteristics" varchar(500)
);
--> statement-breakpoint
CREATE TABLE "suspicious_indicators" (
	"id" serial PRIMARY KEY NOT NULL,
	"analysis_id" integer NOT NULL,
	"type" varchar(255) NOT NULL,
	"severity" varchar(50) NOT NULL,
	"description" text NOT NULL
);
--> statement-breakpoint
ALTER TABLE "analyses" ADD CONSTRAINT "analyses_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "imports" ADD CONSTRAINT "imports_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sections" ADD CONSTRAINT "sections_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "suspicious_indicators" ADD CONSTRAINT "suspicious_indicators_analysis_id_analyses_id_fk" FOREIGN KEY ("analysis_id") REFERENCES "public"."analyses"("id") ON DELETE cascade ON UPDATE no action;