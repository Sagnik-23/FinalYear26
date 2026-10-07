import {
  pgTable,
  serial,
  integer,
  varchar,
  timestamp,
  boolean,
  real,
  text,
} from "drizzle-orm/pg-core";

import { usersTable } from "./users.schema.js";

export const analysesTable = pgTable("analyses", {
  id: serial("id").primaryKey(),

  userId: integer("user_id")
    .references(() => usersTable.id, {
      onDelete: "cascade",
    })
    .notNull(),

  filename: varchar("filename", {
    length: 500,
  }).notNull(),

  originalFilename: varchar("original_filename", {
    length: 500,
  }).notNull(),

  filePath: text("file_path").notNull(),

  fileSize: integer("file_size").notNull(),

  md5: varchar("md5", {
    length: 255,
  }).notNull(),

  sha1: varchar("sha1", {
    length: 255,
  }).notNull(),

  sha256: varchar("sha256", {
    length: 255,
  }).notNull(),

  compileTime: timestamp("compile_time"),

  entryPoint: varchar("entry_point", {
    length: 255,
  }),

  imageBase: varchar("image_base", {
    length: 255,
  }),

  subsystem: varchar("subsystem", {
    length: 255,
  }),

  machineType: varchar("machine_type", {
    length: 255,
  }),

  numberOfSections: integer("number_of_sections"),

  entropy: real("entropy"),

  isPacked: boolean("is_packed").default(false),

  isSuspicious: boolean("is_suspicious").default(false),

  suspiciousScore: integer("suspicious_score").default(0),

  analysisStatus: varchar("analysis_status", {
    length: 50,
  }).default("completed"),

  createdAt: timestamp("created_at")
    .defaultNow()
    .notNull(),
});