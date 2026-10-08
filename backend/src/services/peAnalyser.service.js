import fs from "fs";
import crypto from "crypto";
import { parsePEBinary, calculateEntropy } from "../utils/peParser.js";

/*
|--------------------------------------------------------------------------
| PE Analyzer Service
|--------------------------------------------------------------------------
*/

export const analyzePE = async (filePath) => {
  const buffer = fs.readFileSync(filePath);

  /*
  |--------------------------------------------------------------------------
  | 1. Cryptographic Hashes
  |--------------------------------------------------------------------------
  */
  const md5 = crypto.createHash("md5").update(buffer).digest("hex");
  const sha1 = crypto.createHash("sha1").update(buffer).digest("hex");
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");

  /*
  |--------------------------------------------------------------------------
  | 2. Dynamic PE Binary Parsing
  |--------------------------------------------------------------------------
  */
  try {
    const parsed = parsePEBinary(buffer);

    return {
      md5,
      sha1,
      sha256,
      entropy: parsed.entropy,
      suspiciousScore: parsed.suspiciousScore,
      isPacked: parsed.isPacked,
      isSuspicious: parsed.isSuspicious,
      compileTime: parsed.compileTime,
      entryPoint: parsed.entryPoint,
      imageBase: parsed.imageBase,
      subsystem: parsed.subsystem,
      machineType: parsed.machineType,
      sections: parsed.sections,
      imports: parsed.imports,
      indicators: parsed.indicators,
    };
  } catch (error) {
    console.warn(`[PE Analyzer] Fallback on parsing error: ${error.message}`);
    const overallEntropy = calculateEntropy(buffer);

    return {
      md5,
      sha1,
      sha256,
      entropy: overallEntropy,
      suspiciousScore: overallEntropy > 7 ? 40 : 10,
      isPacked: overallEntropy > 7,
      isSuspicious: overallEntropy > 7,
      compileTime: new Date(),
      entryPoint: "N/A (Raw/Malformed)",
      imageBase: "N/A",
      subsystem: "Unknown (Non-standard PE)",
      machineType: "Raw / Non-PE Executable",
      sections: [
        {
          name: ".raw_data",
          virtualSize: buffer.length,
          rawSize: buffer.length,
          entropy: overallEntropy,
          characteristics: "READ | UNPARSED",
        },
      ],
      imports: [],
      indicators: [
        {
          type: "parser_warning",
          severity: "low",
          description: `Non-standard PE structure: ${error.message}`,
        },
      ],
    };
  }
};