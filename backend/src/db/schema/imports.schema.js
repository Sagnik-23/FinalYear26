import {
  pgTable,
  serial,
  integer,
  varchar,
} from "drizzle-orm/pg-core";

import { analysesTable } from "./analyses.schema.js";

export const importsTable = pgTable("imports", {
  id: serial("id").primaryKey(),

  analysisId: integer("analysis_id")
    .references(() => analysesTable.id, {
      onDelete: "cascade",
    })
    .notNull(),

  dllName: varchar("dll_name", {
    length: 255,
  }).notNull(),

  functionName: varchar("function_name", {
    length: 255,
  }).notNull(),

  isSuspicious: integer("is_suspicious").default(0),
});