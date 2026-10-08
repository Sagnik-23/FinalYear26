import fs from "fs";
import crypto from "crypto";

/*
|--------------------------------------------------------------------------
| Windows PE Parser & Static Feature Extractor
|--------------------------------------------------------------------------
*/

const MACHINE_TYPES = {
  0x014c: "IMAGE_FILE_MACHINE_I386 (x86 32-bit)",
  0x8664: "IMAGE_FILE_MACHINE_AMD64 (x64 64-bit)",
  0x0200: "IMAGE_FILE_MACHINE_IA64 (Intel Itanium)",
  0x01c0: "IMAGE_FILE_MACHINE_ARM (ARM little endian)",
  0xaa64: "IMAGE_FILE_MACHINE_ARM64 (ARM64 little endian)",
};

const SUBSYSTEM_TYPES = {
  1: "Native / Driver",
  2: "Windows GUI",
  3: "Windows CUI (Console)",
  7: "POSIX CUI",
  9: "Windows CE GUI",
  10: "EFI Application",
  11: "EFI Boot Service Driver",
  12: "EFI Runtime Driver",
  14: "Xbox",
};

const SUSPICIOUS_APIS = {
  // Process Injection & Memory Manipulation
  VirtualAlloc: { category: "Memory Allocation", severity: "high", weight: 25 },
  VirtualAllocEx: { category: "Remote Process Injection", severity: "high", weight: 30 },
  VirtualProtect: { category: "Memory Protection Alteration", severity: "high", weight: 25 },
  VirtualProtectEx: { category: "Remote Memory Protection Alteration", severity: "high", weight: 30 },
  WriteProcessMemory: { category: "Process Injection / Memory Modification", severity: "critical", weight: 35 },
  ReadProcessMemory: { category: "Process Snooping / Dump", severity: "medium", weight: 15 },
  CreateRemoteThread: { category: "Remote Code Execution / Injection", severity: "critical", weight: 35 },
  CreateRemoteThreadEx: { category: "Remote Code Execution / Injection", severity: "critical", weight: 35 },
  NtCreateThreadEx: { category: "Undocumented Thread Injection", severity: "critical", weight: 40 },
  QueueUserAPC: { category: "APC Queue Injection", severity: "high", weight: 30 },
  SetThreadContext: { category: "Thread Hijacking", severity: "critical", weight: 35 },
  GetThreadContext: { category: "Thread Context Snooping", severity: "medium", weight: 15 },

  // Execution & Persistence
  WinExec: { category: "Process Execution", severity: "high", weight: 20 },
  ShellExecuteA: { category: "Shell Execution", severity: "high", weight: 20 },
  ShellExecuteW: { category: "Shell Execution", severity: "high", weight: 20 },
  ShellExecuteExA: { category: "Shell Execution", severity: "high", weight: 20 },
  ShellExecuteExW: { category: "Shell Execution", severity: "high", weight: 20 },
  CreateProcessA: { category: "Process Creation", severity: "medium", weight: 15 },
  CreateProcessW: { category: "Process Creation", severity: "medium", weight: 15 },
  CreateProcessInternalW: { category: "Low-level Process Creation", severity: "high", weight: 25 },

  // Anti-Debugging & Evasion
  IsDebuggerPresent: { category: "Anti-Debugging", severity: "medium", weight: 15 },
  CheckRemoteDebuggerPresent: { category: "Anti-Debugging", severity: "medium", weight: 15 },
  NtQueryInformationProcess: { category: "Anti-Debugging / Process Snooping", severity: "high", weight: 25 },
  OutputDebugStringA: { category: "Debug String Obfuscation", severity: "low", weight: 5 },

  // Hooking & Keylogging
  SetWindowsHookExA: { category: "Keylogging / Window Hooking", severity: "high", weight: 30 },
  SetWindowsHookExW: { category: "Keylogging / Window Hooking", severity: "high", weight: 30 },
  GetAsyncKeyState: { category: "Keylogging", severity: "high", weight: 25 },
  GetKeyState: { category: "Keylogging", severity: "medium", weight: 15 },

  // Network & Communication
  InternetOpenA: { category: "HTTP/Network Connection", severity: "medium", weight: 15 },
  InternetOpenUrlA: { category: "C2 / URL Downloader", severity: "high", weight: 25 },
  URLDownloadToFileA: { category: "Payload Dropper / Downloader", severity: "high", weight: 30 },
  URLDownloadToFileW: { category: "Payload Dropper / Downloader", severity: "high", weight: 30 },
  WSAStartup: { category: "Raw Socket Network", severity: "low", weight: 10 },
  connect: { category: "Socket Connection", severity: "medium", weight: 15 },

  // Crypto & Ransomware indicators
  CryptEncrypt: { category: "Cryptographic Encryption (Ransomware indicator)", severity: "medium", weight: 20 },
  CryptDecrypt: { category: "Cryptographic Decryption", severity: "medium", weight: 15 },
  CryptGenKey: { category: "Crypto Key Generation", severity: "medium", weight: 15 },
};

/*
|--------------------------------------------------------------------------
| Calculate Shannon Entropy
|--------------------------------------------------------------------------
*/
export const calculateEntropy = (buffer) => {
  if (!buffer || buffer.length === 0) return 0;
  const frequency = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    frequency[buffer[i]]++;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequency[i] === 0) continue;
    const p = frequency[i] / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
};

/*
|--------------------------------------------------------------------------
| Helper: RVA to File Offset Converter
|--------------------------------------------------------------------------
*/
const rvaToFileOffset = (rva, sections) => {
  for (const sec of sections) {
    if (rva >= sec.virtualAddress && rva < sec.virtualAddress + Math.max(sec.virtualSize, sec.rawSize)) {
      return sec.pointerToRawData + (rva - sec.virtualAddress);
    }
  }
  return null;
};

/*
|--------------------------------------------------------------------------
| Helper: Read Null-Terminated ASCII String
|--------------------------------------------------------------------------
*/
const readAsciiString = (buffer, offset, maxLength = 256) => {
  if (offset < 0 || offset >= buffer.length) return "";
  let end = offset;
  while (end < buffer.length && end - offset < maxLength && buffer[end] !== 0) {
    end++;
  }
  return buffer.toString("ascii", offset, end);
};

/*
|--------------------------------------------------------------------------
| Parse PE Binary Structure
|--------------------------------------------------------------------------
*/
export const parsePEBinary = (buffer) => {
  if (buffer.length < 64) {
    throw new Error("File too small to be a valid Windows PE file.");
  }

  // 1. DOS Header Check ('MZ')
  const dosMagic = buffer.toString("ascii", 0, 2);
  if (dosMagic !== "MZ") {
    throw new Error("Invalid DOS Header signature (Expected 'MZ').");
  }

  // 2. PE Header Offset (e_lfanew at 0x3C)
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 24 > buffer.length) {
    throw new Error("Invalid PE header pointer (e_lfanew points outside buffer).");
  }

  // 3. PE Signature Check ('PE\0\0')
  const peSignature = buffer.readUInt32LE(peOffset);
  if (peSignature !== 0x00004550) {
    throw new Error("Invalid PE Header signature (Expected 'PE\\0\\0').");
  }

  // 4. COFF / File Header (20 bytes starting at peOffset + 4)
  const fileHeaderOffset = peOffset + 4;
  const machine = buffer.readUInt16LE(fileHeaderOffset);
  const numberOfSections = buffer.readUInt16LE(fileHeaderOffset + 2);
  const timeDateStamp = buffer.readUInt32LE(fileHeaderOffset + 4);
  const sizeOfOptionalHeader = buffer.readUInt16LE(fileHeaderOffset + 16);
  const fileCharacteristics = buffer.readUInt16LE(fileHeaderOffset + 18);

  const compileTime = new Date(timeDateStamp * 1000);
  const machineType = MACHINE_TYPES[machine] || `Unknown Architecture (0x${machine.toString(16)})`;

  // 5. Optional Header (if present)
  let is64Bit = false;
  let entryPointRva = 0;
  let imageBase = 0n;
  let subsystem = "Unknown";
  let importDirRva = 0;
  let importDirSize = 0;
  let exportDirRva = 0;
  let exportDirSize = 0;

  const optionalHeaderOffset = fileHeaderOffset + 20;
  if (sizeOfOptionalHeader > 0 && optionalHeaderOffset + sizeOfOptionalHeader <= buffer.length) {
    const magic = buffer.readUInt16LE(optionalHeaderOffset);
    is64Bit = magic === 0x20b; // PE32+ (64-bit)

    entryPointRva = buffer.readUInt32LE(optionalHeaderOffset + 16);

    if (is64Bit) {
      imageBase = buffer.readBigUInt64LE(optionalHeaderOffset + 24);
      const sub = buffer.readUInt16LE(optionalHeaderOffset + 68);
      subsystem = SUBSYSTEM_TYPES[sub] || `Other (${sub})`;

      // Data Directories (offset 112 for PE32+)
      if (sizeOfOptionalHeader >= 128) {
        exportDirRva = buffer.readUInt32LE(optionalHeaderOffset + 112);
        exportDirSize = buffer.readUInt32LE(optionalHeaderOffset + 116);
        importDirRva = buffer.readUInt32LE(optionalHeaderOffset + 120);
        importDirSize = buffer.readUInt32LE(optionalHeaderOffset + 124);
      }
    } else {
      imageBase = BigInt(buffer.readUInt32LE(optionalHeaderOffset + 28));
      const sub = buffer.readUInt16LE(optionalHeaderOffset + 68);
      subsystem = SUBSYSTEM_TYPES[sub] || `Other (${sub})`;

      // Data Directories (offset 96 for PE32)
      if (sizeOfOptionalHeader >= 112) {
        exportDirRva = buffer.readUInt32LE(optionalHeaderOffset + 96);
        exportDirSize = buffer.readUInt32LE(optionalHeaderOffset + 100);
        importDirRva = buffer.readUInt32LE(optionalHeaderOffset + 104);
        importDirSize = buffer.readUInt32LE(optionalHeaderOffset + 108);
      }
    }
  }

  // 6. Section Headers (Immediately following Optional Header, 40 bytes each)
  const sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
  const sections = [];

  for (let i = 0; i < numberOfSections; i++) {
    const secOffset = sectionTableOffset + i * 40;
    if (secOffset + 40 > buffer.length) break;

    const rawName = buffer.toString("ascii", secOffset, secOffset + 8);
    const name = rawName.replace(/\0/g, "").trim() || `.sec_${i}`;
    const virtualSize = buffer.readUInt32LE(secOffset + 8);
    const virtualAddress = buffer.readUInt32LE(secOffset + 12);
    const rawSize = buffer.readUInt32LE(secOffset + 16);
    const pointerToRawData = buffer.readUInt32LE(secOffset + 20);
    const characteristics = buffer.readUInt32LE(secOffset + 36);

    // Compute real section entropy if raw data exists
    let sectionEntropy = 0;
    if (pointerToRawData > 0 && rawSize > 0 && pointerToRawData + rawSize <= buffer.length) {
      const sectionSlice = buffer.subarray(pointerToRawData, pointerToRawData + rawSize);
      sectionEntropy = calculateEntropy(sectionSlice);
    }

    // Decode characteristics flags
    const charFlags = [];
    if (characteristics & 0x00000020) charFlags.push("CODE");
    if (characteristics & 0x00000040) charFlags.push("INITIALIZED_DATA");
    if (characteristics & 0x00000080) charFlags.push("UNINITIALIZED_DATA");
    if (characteristics & 0x20000000) charFlags.push("EXECUTE");
    if (characteristics & 0x40000000) charFlags.push("READ");
    if (characteristics & 0x80000000) charFlags.push("WRITE");

    sections.push({
      name,
      virtualSize,
      virtualAddress,
      rawSize,
      pointerToRawData,
      entropy: sectionEntropy,
      characteristics: charFlags.join(" | ") || "NONE",
      rawCharacteristics: characteristics,
      isExecutable: (characteristics & 0x20000000) !== 0,
      isWritable: (characteristics & 0x80000000) !== 0,
    });
  }

  // 7. Parse Real Import Table (Import Directory Descriptors)
  const imports = [];
  if (importDirRva > 0 && importDirSize > 0) {
    let importDescOffset = rvaToFileOffset(importDirRva, sections);

    if (importDescOffset && importDescOffset < buffer.length) {
      while (importDescOffset + 20 <= buffer.length) {
        const originalFirstThunk = buffer.readUInt32LE(importDescOffset);
        const timeStamp = buffer.readUInt32LE(importDescOffset + 4);
        const forwarderChain = buffer.readUInt32LE(importDescOffset + 8);
        const nameRva = buffer.readUInt32LE(importDescOffset + 12);
        const firstThunk = buffer.readUInt32LE(importDescOffset + 16);

        // Null descriptor terminates the array
        if (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0) {
          break;
        }

        const dllNameOffset = rvaToFileOffset(nameRva, sections);
        const dllName = dllNameOffset ? readAsciiString(buffer, dllNameOffset) : "Unknown.dll";

        // Thunk table offset (Prefer OriginalFirstThunk / Import Lookup Table, fallback to FirstThunk)
        const thunkRva = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
        let thunkOffset = rvaToFileOffset(thunkRva, sections);

        if (thunkOffset && thunkOffset < buffer.length) {
          let funcIdx = 0;
          while (thunkOffset < buffer.length && funcIdx < 500) {
            let isOrdinal = false;
            let functionName = "";

            if (is64Bit) {
              if (thunkOffset + 8 > buffer.length) break;
              const thunkVal = buffer.readBigUInt64LE(thunkOffset);
              if (thunkVal === 0n) break;
              if (thunkVal & 0x8000000000000000n) {
                isOrdinal = true;
                functionName = `Ordinal_${Number(thunkVal & 0xffffn)}`;
              } else {
                const hintNameOffset = rvaToFileOffset(Number(thunkVal & 0x7fffffffn), sections);
                if (hintNameOffset && hintNameOffset + 2 < buffer.length) {
                  functionName = readAsciiString(buffer, hintNameOffset + 2);
                }
              }
              thunkOffset += 8;
            } else {
              if (thunkOffset + 4 > buffer.length) break;
              const thunkVal = buffer.readUInt32LE(thunkOffset);
              if (thunkVal === 0) break;
              if (thunkVal & 0x80000000) {
                isOrdinal = true;
                functionName = `Ordinal_${thunkVal & 0xffff}`;
              } else {
                const hintNameOffset = rvaToFileOffset(thunkVal & 0x7fffffff, sections);
                if (hintNameOffset && hintNameOffset + 2 < buffer.length) {
                  functionName = readAsciiString(buffer, hintNameOffset + 2);
                }
              }
              thunkOffset += 4;
            }

            if (functionName) {
              imports.push({
                dllName,
                functionName,
                isOrdinal,
                isSuspicious: SUSPICIOUS_APIS[functionName] ? 1 : 0,
              });
            }
            funcIdx++;
          }
        }

        importDescOffset += 20;
      }
    }
  }

  // 8. Indicators & Risk Heuristics Evaluation
  const indicators = [];
  let suspiciousScore = 0;

  // Rule: High Section or Overall Entropy (Packed / Obfuscated)
  const overallEntropy = calculateEntropy(buffer);
  if (overallEntropy > 7.1) {
    indicators.push({
      type: "entropy",
      severity: "high",
      description: `High overall file entropy (${overallEntropy}/8.0). High probability of packed/encrypted binary payload.`,
    });
    suspiciousScore += 30;
  }

  // Rule: Anomalous Section Entropies
  for (const sec of sections) {
    if (sec.entropy > 7.3) {
      indicators.push({
        type: "section_entropy",
        severity: "high",
        description: `Section ${sec.name} has suspicious entropy of ${sec.entropy}, indicating packed bytecode or payload shellcode.`,
      });
      suspiciousScore += 20;
    }

    // Writable & Executable section (W^X violation - common in self-modifying malware)
    if (sec.isExecutable && sec.isWritable) {
      indicators.push({
        type: "wx_section",
        severity: "critical",
        description: `Section ${sec.name} is both WRITABLE and EXECUTABLE (W^X violation), commonly used for code injection & unpacking stubs.`,
      });
      suspiciousScore += 35;
    }
  }

  // Rule: Suspicious API evaluation
  const detectedApis = new Set();
  for (const imp of imports) {
    const apiMeta = SUSPICIOUS_APIS[imp.functionName];
    if (apiMeta && !detectedApis.has(imp.functionName)) {
      detectedApis.add(imp.functionName);
      indicators.push({
        type: "suspicious_api",
        severity: apiMeta.severity,
        description: `Imported API '${imp.functionName}' from ${imp.dllName} (${apiMeta.category}).`,
      });
      suspiciousScore += apiMeta.weight;
    }
  }

  // Cap risk score between 0 and 100
  const normalizedScore = Math.min(Math.max(suspiciousScore, 0), 100);

  return {
    entryPoint: `0x${entryPointRva.toString(16)}`,
    imageBase: `0x${imageBase.toString(16)}`,
    machineType,
    subsystem,
    is64Bit,
    sections,
    imports,
    indicators,
    entropy: overallEntropy,
    suspiciousScore: normalizedScore,
    isPacked: overallEntropy > 7.0 || sections.some((s) => s.entropy > 7.3),
    isSuspicious: normalizedScore >= 40,
    compileTime,
  };
};
