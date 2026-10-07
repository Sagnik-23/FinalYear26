import express from "express";

import {
  analyzePEFile,
  getAnalysisById,
  getHistory,
} from "../controllers/analysis.controller.js";

import { verifyToken } from "../middleware/auth.middleware.js";

import { upload } from "../middleware/upload.middleware.js";

const router = express.Router();

/*
|--------------------------------------------------------------------------
| Upload & Analyze
|--------------------------------------------------------------------------
*/

router.post(
  "/upload",
  verifyToken,
  upload.single("file"),
  analyzePEFile
);

/*
|--------------------------------------------------------------------------
| User History
|--------------------------------------------------------------------------
*/

router.get(
  "/history",
  verifyToken,
  getHistory
);

router.get(
  "/:id",
  verifyToken,
  getAnalysisById
);

export default router;