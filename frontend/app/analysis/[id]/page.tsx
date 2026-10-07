"use client";

import { useEffect, useState } from "react";

import { useParams } from "next/navigation";

import {
  Terminal,
  Loader2,
  ShieldAlert,
} from "lucide-react";

import api from "@/lib/axios";

interface Analysis {
  id: number;

  filename: string;

  entropy: number;

  suspiciousScore: number;

  entryPoint: string;

  machineType: string;

  subsystem: string;

  imports: any[];

  sections: any[];

  indicators: any[];
}

export default function AnalysisPage() {
  const params = useParams();

  const [loading, setLoading] =
    useState(true);

  const [analysis, setAnalysis] =
    useState<Analysis | null>(null);

  const [lines, setLines] =
    useState<string[]>([]);

  /*
  |--------------------------------------------------------------------------
  | Fetch Analysis
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        const res = await api.get(
          `/analyze/${params.id}`
        );

        setAnalysis(res.data.analysis);
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    };

    fetchAnalysis();
  }, [params.id]);

  /*
  |--------------------------------------------------------------------------
  | Terminal Animation
  |--------------------------------------------------------------------------
  */

  useEffect(() => {
  if (!analysis) return;

  /*
  |--------------------------------------------------------------------------
  | Build Terminal Lines
  |--------------------------------------------------------------------------
  */

  const terminalLines = [
    "[BOOT] Initializing PE Guardian...",

    `[FILE] ${analysis.filename}`,

    "[SCAN] Parsing PE headers...",

    `[PE] Entry Point: ${analysis.entryPoint}`,

    `[PE] Machine Type: ${analysis.machineType}`,

    `[PE] Subsystem: ${analysis.subsystem}`,

    `[ENTROPY] ${analysis.entropy}`,

    `[RISK SCORE] ${analysis.suspiciousScore}%`,

    "[IMPORTS] Enumerating APIs...",

    ...(analysis.imports || []).map(
      (imp: any) =>
        `[API] ${imp.functionName}`
    ),

    "[SECTIONS] Enumerating sections...",

    ...(analysis.sections || []).map(
      (section: any) =>
        `[SECTION] ${section.name}`
    ),

    "[DONE] Analysis Completed",
  ];

  /*
  |--------------------------------------------------------------------------
  | Reset Previous Lines
  |--------------------------------------------------------------------------
  */

  setLines([]);

  let current = 0;

  const interval = setInterval(() => {
    /*
    |--------------------------------------------------------------------------
    | Stop BEFORE undefined
    |--------------------------------------------------------------------------
    */

    if (
      current >= terminalLines.length
    ) {
      clearInterval(interval);

      return;
    }

    const nextLine =
      terminalLines[current];

    /*
    |--------------------------------------------------------------------------
    | Prevent undefined
    |--------------------------------------------------------------------------
    */

    if (nextLine) {
      setLines((prev) => [
        ...prev,
        nextLine,
      ]);
    }

    current++;
  }, 300);

  return () =>
    clearInterval(interval);
}, [analysis]);

  /*
  |--------------------------------------------------------------------------
  | Loading
  |--------------------------------------------------------------------------
  */

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-black">
        <Loader2 className="h-10 w-10 animate-spin text-emerald-400" />
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-black text-white">
        Analysis not found
      </div>
    );
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-black text-white">
      {/* Background */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,255,170,0.15),transparent_35%)]" />

      {/* Grid */}
      <div className="absolute inset-0 opacity-20">
        <div className="h-full w-full bg-[linear-gradient(to_right,#0f0f0f_1px,transparent_1px),linear-gradient(to_bottom,#0f0f0f_1px,transparent_1px)] bg-[size:4rem_4rem]" />
      </div>

      <div className="relative z-10 mx-auto max-w-7xl px-6 py-14">
        {/* Header */}
        <div className="mb-10 flex items-center justify-between">
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-400">
              <ShieldAlert className="h-4 w-4" />
              PE Analysis
            </div>

            <h1 className="text-5xl font-black">
              {analysis.filename}
            </h1>
          </div>

          <div
            className={`rounded-3xl border px-8 py-6 ${
              analysis.suspiciousScore >
              70
                ? "border-red-500/30 bg-red-500/10"
                : analysis.suspiciousScore >
                  40
                ? "border-yellow-500/30 bg-yellow-500/10"
                : "border-emerald-500/30 bg-emerald-500/10"
            }`}
          >
            <p className="text-sm text-zinc-400">
              Risk Score
            </p>

            <h2 className="mt-2 text-5xl font-black">
              {
                analysis.suspiciousScore
              }
              %
            </h2>
          </div>
        </div>

        {/* Terminal */}
        <div className="overflow-hidden rounded-3xl border border-white/10 bg-black/60 shadow-2xl backdrop-blur-2xl">
          {/* Top */}
          <div className="flex items-center gap-2 border-b border-white/10 px-6 py-4">
            <div className="h-3 w-3 rounded-full bg-red-500" />
            <div className="h-3 w-3 rounded-full bg-yellow-500" />
            <div className="h-3 w-3 rounded-full bg-green-500" />

            <div className="ml-4 flex items-center gap-2 text-sm text-zinc-500">
              <Terminal className="h-4 w-4" />
              pe_guardian_terminal.exe
            </div>
          </div>

          {/* Body */}
          <div className="h-[500px] overflow-y-auto p-6 font-mono text-sm">
            {lines.map(
              (line, index) => (
                <div
                  key={index}
                  className={`mb-3 animate-fadeIn ${
                    line?.includes(
                      "RISK"
                    )
                      ? "text-red-400"
                      : line?.includes(
                          "DONE"
                        )
                      ? "text-emerald-400"
                      : "text-emerald-300"
                  }`}
                >
                  <span className="mr-2 text-zinc-600">
                    root@guardian:~$
                  </span>

                  {line}
                </div>
              )
            )}

            <div className="mt-2 flex items-center text-emerald-400">
              <span className="mr-2 text-zinc-600">
                root@guardian:~$
              </span>

              <div className="h-5 w-2 animate-pulse bg-emerald-400" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}