import fs from "fs";

import crypto from "crypto";

/*
|--------------------------------------------------------------------------
| Calculate Entropy
|--------------------------------------------------------------------------
*/

const calculateEntropy = (buffer) => {
  const frequency =
    new Array(256).fill(0);

  for (const byte of buffer) {
    frequency[byte]++;
  }

  let entropy = 0;

  for (const count of frequency) {
    if (count === 0) continue;

    const p = count / buffer.length;

    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(2));
};

/*
|--------------------------------------------------------------------------
| Suspicious APIs
|--------------------------------------------------------------------------
*/

const suspiciousApis = [
  "VirtualAlloc",
  "WriteProcessMemory",
  "CreateRemoteThread",
  "WinExec",
  "ShellExecuteA",
];

/*
|--------------------------------------------------------------------------
| Analyze PE
|--------------------------------------------------------------------------
*/

export const analyzePE = async (
  filePath
) => {
  const buffer =
    fs.readFileSync(filePath);

  /*
  |--------------------------------------------------------------------------
  | Hashes
  |--------------------------------------------------------------------------
  */

  const md5 = crypto
    .createHash("md5")
    .update(buffer)
    .digest("hex");

  const sha1 = crypto
    .createHash("sha1")
    .update(buffer)
    .digest("hex");

  const sha256 = crypto
    .createHash("sha256")
    .update(buffer)
    .digest("hex");

  /*
  |--------------------------------------------------------------------------
  | Entropy
  |--------------------------------------------------------------------------
  */

  const entropy =
    calculateEntropy(buffer);

  /*
  |--------------------------------------------------------------------------
  | Demo Sections
  |--------------------------------------------------------------------------
  */

  const sections = [
    {
      name: ".text",
      virtualSize: 4096,
      rawSize: 2048,
      entropy: 6.4,
      characteristics:
        "CODE | EXECUTE | READ",
    },

    {
      name: ".rsrc",
      virtualSize: 2048,
      rawSize: 1024,
      entropy: 7.8,
      characteristics:
        "READ | WRITE",
    },
  ];

  /*
  |--------------------------------------------------------------------------
  | Demo Imports
  |--------------------------------------------------------------------------
  */

  const imports = [
    {
      dllName: "kernel32.dll",
      functionName:
        "VirtualAlloc",
    },

    {
      dllName: "kernel32.dll",
      functionName:
        "CreateRemoteThread",
    },

    {
      dllName: "user32.dll",
      functionName: "MessageBoxA",
    },
  ];

  /*
  |--------------------------------------------------------------------------
  | Indicators
  |--------------------------------------------------------------------------
  */

  const indicators = [];

  let suspiciousScore = 0;

  /*
  |--------------------------------------------------------------------------
  | Entropy Detection
  |--------------------------------------------------------------------------
  */

  if (entropy > 7) {
    indicators.push({
      type: "entropy",

      severity: "high",

      description:
        "High entropy detected. File may be packed.",
    });

    suspiciousScore += 30;
  }

  /*
  |--------------------------------------------------------------------------
  | Suspicious Imports
  |--------------------------------------------------------------------------
  */

  imports.forEach((imp) => {
    if (
      suspiciousApis.includes(
        imp.functionName
      )
    ) {
      indicators.push({
        type: "api",

        severity: "medium",

        description: `Suspicious API detected: ${imp.functionName}`,
      });

      suspiciousScore += 20;

      imp.isSuspicious = 1;
    }
  });

  return {
    md5,

    sha1,

    sha256,

    entropy,

    suspiciousScore,

    isPacked: entropy > 7,

    isSuspicious:
      suspiciousScore > 40,

    compileTime: new Date(),

    entryPoint: "0x401000",

    imageBase: "0x400000",

    subsystem: "Windows GUI",

    machineType: "x86",

    sections,

    imports,

    indicators,
  };
};