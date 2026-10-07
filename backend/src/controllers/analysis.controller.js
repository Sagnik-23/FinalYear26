import { db } from "../db/index.js";

import {
  analysesTable,
} from "../db/schema/analyses.schema.js";

import {
  sectionsTable,
} from "../db/schema/sections.schema.js";

import {
  importsTable,
} from "../db/schema/imports.schema.js";

import {
  suspiciousIndicatorsTable,
} from "../db/schema/suspiciousIndicator.schema.js";

import { eq } from "drizzle-orm";

import { analyzePE } from "../services/peAnalyser.service.js";

/*
|--------------------------------------------------------------------------
| Upload & Analyze
|--------------------------------------------------------------------------
*/

export const analyzePEFile = async (
  req,
  res
) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No file uploaded",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Analyze File
    |--------------------------------------------------------------------------
    */

    const result =
      await analyzePE(
        req.file.path
      );

    /*
    |--------------------------------------------------------------------------
    | Save Analysis
    |--------------------------------------------------------------------------
    */

    const analysis =
      await db
        .insert(analysesTable)
        .values({
          userId: req.user.id,

          filename:
            req.file.filename,

          originalFilename:
            req.file.originalname,

          filePath: req.file.path,

          fileSize:
            req.file.size,

          md5: result.md5,

          sha1: result.sha1,

          sha256: result.sha256,

          compileTime:
            result.compileTime,

          entryPoint:
            result.entryPoint,

          imageBase:
            result.imageBase,

          subsystem:
            result.subsystem,

          machineType:
            result.machineType,

          numberOfSections:
            result.sections.length,

          entropy:
            result.entropy,

          isPacked:
            result.isPacked,

          isSuspicious:
            result.isSuspicious,

          suspiciousScore:
            result.suspiciousScore,
        })
        .returning();

    const analysisId =
      analysis[0].id;

    /*
    |--------------------------------------------------------------------------
    | Save Sections
    |--------------------------------------------------------------------------
    */

    for (const section of result.sections) {
      await db
        .insert(sectionsTable)
        .values({
          analysisId,

          name: section.name,

          virtualSize:
            section.virtualSize,

          rawSize:
            section.rawSize,

          entropy:
            section.entropy,

          characteristics:
            section.characteristics,
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Save Imports
    |--------------------------------------------------------------------------
    */

    for (const imp of result.imports) {
      await db
        .insert(importsTable)
        .values({
          analysisId,

          dllName: imp.dllName,

          functionName:
            imp.functionName,

          isSuspicious:
            imp.isSuspicious || 0,
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Save Indicators
    |--------------------------------------------------------------------------
    */

    for (const indicator of result.indicators) {
      await db
        .insert(
          suspiciousIndicatorsTable
        )
        .values({
          analysisId,

          type: indicator.type,

          severity:
            indicator.severity,

          description:
            indicator.description,
        });
    }

    return res.status(200).json({
      success: true,

      analysisId,

      ...result,
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,

      message:
        "Analysis failed",
    });
  }
};

/*
|--------------------------------------------------------------------------
| Get History
|--------------------------------------------------------------------------
*/

export const getHistory = async (
  req,
  res
) => {
  try {
    const analyses = await db
      .select()
      .from(analysesTable)
      .where(
        eq(
          analysesTable.userId,
          req.user.id
        )
      );

    return res.status(200).json({
      success: true,

      analyses,
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,

      message:
        "Failed to fetch history",
    });
  }
};

/*
|--------------------------------------------------------------------------
| Get Single Analysis
|--------------------------------------------------------------------------
*/

export const getAnalysisById =
  async (req, res) => {
    try {
      const { id } = req.params;

      /*
      |--------------------------------------------------------------------------
      | Get Analysis
      |--------------------------------------------------------------------------
      */

      const analysis =
        await db
          .select()
          .from(analysesTable)
          .where(
            eq(
              analysesTable.id,
              Number(id)
            )
          );

      if (
        analysis.length === 0
      ) {
        return res.status(404).json({
          success: false,
          message:
            "Analysis not found",
        });
      }

      /*
      |--------------------------------------------------------------------------
      | Get Sections
      |--------------------------------------------------------------------------
      */

      const sections =
        await db
          .select()
          .from(sectionsTable)
          .where(
            eq(
              sectionsTable.analysisId,
              Number(id)
            )
          );

      /*
      |--------------------------------------------------------------------------
      | Get Imports
      |--------------------------------------------------------------------------
      */

      const imports =
        await db
          .select()
          .from(importsTable)
          .where(
            eq(
              importsTable.analysisId,
              Number(id)
            )
          );

      /*
      |--------------------------------------------------------------------------
      | Get Indicators
      |--------------------------------------------------------------------------
      */

      const indicators =
        await db
          .select()
          .from(
            suspiciousIndicatorsTable
          )
          .where(
            eq(
              suspiciousIndicatorsTable.analysisId,
              Number(id)
            )
          );

      /*
      |--------------------------------------------------------------------------
      | Return Full Analysis
      |--------------------------------------------------------------------------
      */

      return res.status(200).json({
        success: true,

        analysis: {
          ...analysis[0],

          sections,

          imports,

          indicators,
        },
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        success: false,

        message:
          "Failed to fetch analysis",
      });
    }
  };