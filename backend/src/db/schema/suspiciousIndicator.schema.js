import {
  pgTable,
  serial,
  integer,
  text,
  varchar,
} from "drizzle-orm/pg-core";

import { analysesTable } from "./analyses.schema.js";

export const suspiciousIndicatorsTable = pgTable(
  "suspicious_indicators",
  {
    id: serial("id").primaryKey(),

    analysisId: integer("analysis_id")
      .references(() => analysesTable.id, {
        onDelete: "cascade",
      })
      .notNull(),

    type: varchar("type", {
      length: 255,
    }).notNull(),

    severity: varchar("severity", {
      length: 50,
    }).notNull(),

    description: text("description").notNull(),
  }
);