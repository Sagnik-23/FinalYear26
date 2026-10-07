import {
  pgTable,
  serial,
  integer,
  varchar,
  real,
} from "drizzle-orm/pg-core";

import { analysesTable } from "./analyses.schema.js";

export const sectionsTable = pgTable("sections", {
  id: serial("id").primaryKey(),

  analysisId: integer("analysis_id")
    .references(() => analysesTable.id, {
      onDelete: "cascade",
    })
    .notNull(),

  name: varchar("name", {
    length: 100,
  }).notNull(),

  virtualSize: integer("virtual_size"),

  rawSize: integer("raw_size"),

  entropy: real("entropy"),

  characteristics: varchar("characteristics", {
    length: 500,
  }),
});