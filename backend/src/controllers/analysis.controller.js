import fs from "fs";
import crypto from "crypto";
import { db } from "../db/index.js";
import { analysesTable } from "../db/schema/analyses.schema.js";
import { sectionsTable } from "../db/schema/sections.schema.js";
import { importsTable } from "../db/schema/imports.schema.js";
import { suspiciousIndicatorsTable } from "../db/schema/suspiciousIndicator.schema.js";
import { eq, desc } from "drizzle-orm";
import { analyzePE } from "../services/peAnalyser.service.js";
import { extractFeatureVector, classifyAndExplain } from "../services/mlInference.service.js";

/*
|--------------------------------------------------------------------------
| Upload & Analyze with SHA-256 Adaptive Memory + ML & SHAP Pipeline
|--------------------------------------------------------------------------
*/

export const analyzePEFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No file uploaded",
      });
    }

    const fileBuffer = fs.readFileSync(req.file.path);
    const sha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");

    /*
    |--------------------------------------------------------------------------
    | 1. Adaptive Memory Check (Instant Cache Hit)
    |--------------------------------------------------------------------------
    */
    const existingAnalysis = await db
      .select()
      .from(analysesTable)
      .where(eq(analysesTable.sha256, sha256))
      .orderBy(desc(analysesTable.createdAt))
      .limit(1);

    if (existingAnalysis && existingAnalysis.length > 0) {
      const match = existingAnalysis[0];
      const matchId = match.id;

      // Load cached sections, imports, and indicators
      const [sections, imports, indicators] = await Promise.all([
        db.select().from(sectionsTable).where(eq(sectionsTable.analysisId, matchId)),
        db.select().from(importsTable).where(eq(importsTable.analysisId, matchId)),
        db.select().from(suspiciousIndicatorsTable).where(eq(suspiciousIndicatorsTable.analysisId, matchId)),
      ]);

      const userScan = await db
        .insert(analysesTable)
        .values({
          userId: req.user.id,
          filename: req.file.filename,
          originalFilename: req.file.originalname,
          filePath: req.file.path,
          fileSize: req.file.size,
          md5: match.md5,
          sha1: match.sha1,
          sha256: match.sha256,
          compileTime: match.compileTime,
          entryPoint: match.entryPoint,
          imageBase: match.imageBase,
          subsystem: match.subsystem,
          machineType: match.machineType,
          numberOfSections: match.numberOfSections,
          entropy: match.entropy,
          isPacked: match.isPacked,
          isSuspicious: match.isSuspicious,
          suspiciousScore: match.suspiciousScore,
          malwareFamily: match.malwareFamily || "Benign",
          confidence: match.confidence || 0.95,
          familyProbabilities: match.familyProbabilities,
          shapExplanation: match.shapExplanation,
          featureVector: match.featureVector,
          analysisStatus: "completed",
        })
        .returning();

      const newAnalysisId = userScan[0].id;

      for (const section of sections) {
        await db.insert(sectionsTable).values({
          analysisId: newAnalysisId,
          name: section.name,
          virtualSize: section.virtualSize,
          rawSize: section.rawSize,
          entropy: section.entropy,
          characteristics: section.characteristics,
        });
      }

      for (const imp of imports) {
        await db.insert(importsTable).values({
          analysisId: newAnalysisId,
          dllName: imp.dllName,
          functionName: imp.functionName,
          isSuspicious: imp.isSuspicious || 0,
        });
      }

      for (const indicator of indicators) {
        await db.insert(suspiciousIndicatorsTable).values({
          analysisId: newAnalysisId,
          type: indicator.type,
          severity: indicator.severity,
          description: indicator.description,
        });
      }

      return res.status(200).json({
        success: true,
        analysisId: newAnalysisId,
        fromAdaptiveMemory: true,
        md5: match.md5,
        sha1: match.sha1,
        sha256: match.sha256,
        entropy: match.entropy,
        suspiciousScore: match.suspiciousScore,
        isPacked: match.isPacked,
        isSuspicious: match.isSuspicious,
        malwareFamily: match.malwareFamily || "Benign",
        confidence: match.confidence || 0.95,
        familyProbabilities: match.familyProbabilities,
        shapExplanation: match.shapExplanation,
        featureVector: match.featureVector,
        compileTime: match.compileTime,
        entryPoint: match.entryPoint,
        imageBase: match.imageBase,
        subsystem: match.subsystem,
        machineType: match.machineType,
        sections,
        imports,
        indicators,
      });
    }

    /*
    |--------------------------------------------------------------------------
    | 2. Deep Static PE Analysis & Feature Extraction
    |--------------------------------------------------------------------------
    */
    const result = await analyzePE(req.file.path);

    // Build EMBER feature vector and perform ML classification + SHAP explanation
    const featureVector = extractFeatureVector(result, req.file.size);
    const mlResults = classifyAndExplain(featureVector);

    const analysis = await db
      .insert(analysesTable)
      .values({
        userId: req.user.id,
        filename: req.file.filename,
        originalFilename: req.file.originalname,
        filePath: req.file.path,
        fileSize: req.file.size,
        md5: result.md5,
        sha1: result.sha1,
        sha256: result.sha256,
        compileTime: result.compileTime,
        entryPoint: result.entryPoint,
        imageBase: result.imageBase,
        subsystem: result.subsystem,
        machineType: result.machineType,
        numberOfSections: result.sections.length,
        entropy: result.entropy,
        isPacked: result.isPacked,
        isSuspicious: mlResults.predictedFamily !== "Benign" || result.isSuspicious,
        suspiciousScore: mlResults.predictedFamily !== "Benign" ? Math.max(result.suspiciousScore, Math.round(mlResults.confidence * 100)) : result.suspiciousScore,
        malwareFamily: mlResults.predictedFamily,
        confidence: mlResults.confidence,
        familyProbabilities: mlResults.probabilities,
        shapExplanation: mlResults.shapContributions,
        featureVector: featureVector,
        analysisStatus: "completed",
      })
      .returning();

    const analysisId = analysis[0].id;

    // Save Sections
    for (const section of result.sections) {
      await db.insert(sectionsTable).values({
        analysisId,
        name: section.name,
        virtualSize: section.virtualSize,
        rawSize: section.rawSize,
        entropy: section.entropy,
        characteristics: section.characteristics,
      });
    }

    // Save Imports
    for (const imp of result.imports) {
      await db.insert(importsTable).values({
        analysisId,
        dllName: imp.dllName,
        functionName: imp.functionName,
        isSuspicious: imp.isSuspicious || 0,
      });
    }

    // Save Indicators
    for (const indicator of result.indicators) {
      await db.insert(suspiciousIndicatorsTable).values({
        analysisId,
        type: indicator.type,
        severity: indicator.severity,
        description: indicator.description,
      });
    }

    return res.status(200).json({
      success: true,
      analysisId,
      fromAdaptiveMemory: false,
      malwareFamily: mlResults.predictedFamily,
      confidence: mlResults.confidence,
      familyProbabilities: mlResults.probabilities,
      shapExplanation: mlResults.shapContributions,
      featureVector,
      ...result,
    });
  } catch (error) {
    console.error("[Analysis Error]", error);
    return res.status(500).json({
      success: false,
      message: "Analysis failed",
      error: error.message,
    });
  }
};

/*
|--------------------------------------------------------------------------
| Get History
|--------------------------------------------------------------------------
*/
export const getHistory = async (req, res) => {
  try {
    const analyses = await db
      .select()
      .from(analysesTable)
      .where(eq(analysesTable.userId, req.user.id))
      .orderBy(desc(analysesTable.createdAt));

    return res.status(200).json({
      success: true,
      analyses,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Failed to fetch history",
    });
  }
};

/*
|--------------------------------------------------------------------------
| Get Single Analysis
|--------------------------------------------------------------------------
*/
export const getAnalysisById = async (req, res) => {
  try {
    const { id } = req.params;

    const analysis = await db
      .select()
      .from(analysesTable)
      .where(eq(analysesTable.id, Number(id)));

    if (analysis.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Analysis not found",
      });
    }

    const [sections, imports, indicators] = await Promise.all([
      db.select().from(sectionsTable).where(eq(sectionsTable.analysisId, Number(id))),
      db.select().from(importsTable).where(eq(importsTable.analysisId, Number(id))),
      db.select().from(suspiciousIndicatorsTable).where(eq(suspiciousIndicatorsTable.analysisId, Number(id))),
    ]);

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
      message: "Failed to fetch analysis",
    });
  }
};