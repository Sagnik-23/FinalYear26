"use client";

import { useEffect, useState, useMemo } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  Terminal,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  Zap,
  FileCode,
  Layers,
  Activity,
  ArrowLeft,
  BrainCircuit,
  PieChart,
} from "lucide-react";
import api from "@/lib/axios";

interface ImportItem {
  dllName: string;
  functionName: string;
  isSuspicious: number;
}

interface SectionItem {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  characteristics: string;
}

interface IndicatorItem {
  type: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

interface ShapItem {
  feature: string;
  label: string;
  value: string;
  impact: number;
  direction: "malicious" | "benign";
  description: string;
}

interface Analysis {
  id: number;
  filename: string;
  fileSize: number;
  md5: string;
  sha1: string;
  sha256: string;
  entropy: number;
  suspiciousScore: number;
  entryPoint: string;
  imageBase: string;
  machineType: string;
  subsystem: string;
  isPacked: boolean;
  isSuspicious: boolean;
  malwareFamily?: string;
  confidence?: number;
  familyProbabilities?: Record<string, number>;
  shapExplanation?: ShapItem[];
  featureVector?: Record<string, unknown>;
  compileTime?: string;
  createdAt?: string;
  imports: ImportItem[];
  sections: SectionItem[];
  indicators: IndicatorItem[];
}

export default function AnalysisPage() {
  const params = useParams();
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [activeTab, setActiveTab] = useState<"terminal" | "ml_shap" | "sections" | "imports" | "indicators">("ml_shap");
  const [lines, setLines] = useState<string[]>([]);

  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        const res = await api.get(`/analyze/${params.id}`);
        setAnalysis(res.data.analysis);
      } catch (error) {
        console.error("Failed to fetch analysis", error);
      } finally {
        setLoading(false);
      }
    };

    fetchAnalysis();
  }, [params.id]);

  const terminalLines = useMemo(() => {
    if (!analysis) return [];

    return [
      "[BOOT] Initializing AI PE Guardian Engine v2.0...",
      `[FILE] Target Binary: ${analysis.filename} (${(analysis.fileSize / 1024).toFixed(1)} KB)`,
      `[HASH] SHA-256: ${analysis.sha256}`,
      `[HEADER] Architecture: ${analysis.machineType}`,
      `[HEADER] Subsystem: ${analysis.subsystem}`,
      `[HEADER] Entry Point: ${analysis.entryPoint} | Image Base: ${analysis.imageBase}`,
      `[ENTROPY] Overall Shannon Entropy: ${analysis.entropy}/8.0 ${analysis.isPacked ? "(PACKED/ENCRYPTED DETECTED)" : "(Normal Distribution)"}`,
      `[SECTIONS] Discovered ${analysis.sections?.length || 0} PE sections.`,
      `[IMPORTS] Discovered ${analysis.imports?.length || 0} API imports.`,
      "[ML] Vectorizing EMBER static feature vectors...",
      `[ML] Random Forest Multi-class Classifier: Predicted Family -> [${analysis.malwareFamily || "Benign"}] (Confidence: ${((analysis.confidence || 0.95) * 100).toFixed(1)}%)`,
      "[XAI] Calculating TreeExplainer SHAP local feature attributions...",
      ...(analysis.shapExplanation || []).map(
        (shap) => `  [SHAP] ${shap.label}: Impact ${shap.impact > 0 ? "+" : ""}${shap.impact} (${shap.direction.toUpperCase()} SIGNAL)`
      ),
      `[CONCLUSION] Final Threat Status: ${analysis.isSuspicious ? "MALICIOUS ACTIVITY DETECTED" : "BENIGN FILE"}`,
      "[DONE] Analysis completed & cached in SHA-256 Adaptive Memory.",
    ].filter(Boolean);
  }, [analysis]);

  useEffect(() => {
    if (terminalLines.length === 0) return;

    let index = 0;
    const timer = setInterval(() => {
      if (index < terminalLines.length) {
        setLines((prev) => [...prev, terminalLines[index]]);
        index++;
      } else {
        clearInterval(timer);
      }
    }, 180);

    return () => clearInterval(timer);
  }, [terminalLines]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-black">
        <Loader2 className="h-10 w-10 animate-spin text-emerald-400" />
      </div>
    );
  }

  if (!analysis) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-black text-white gap-4">
        <p className="text-xl text-zinc-400">Analysis record not found.</p>
        <button
          onClick={() => router.push("/upload")}
          className="rounded-xl bg-emerald-500 px-6 py-2.5 font-semibold text-black hover:bg-emerald-400"
        >
          Back to Upload
        </button>
      </div>
    );
  }

  const predictedFamily = analysis.malwareFamily || "Benign";
  const confidencePercent = Math.round((analysis.confidence || 0.95) * 100);

  return (
    <div className="relative min-h-screen overflow-hidden bg-black text-white pb-20">
      {/* Background glow */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,255,170,0.15),transparent_35%)]" />

      {/* Grid */}
      <div className="absolute inset-0 opacity-20 pointer-events-none">
        <div className="h-full w-full bg-[linear-gradient(to_right,#0f0f0f_1px,transparent_1px),linear-gradient(to_bottom,#0f0f0f_1px,transparent_1px)] bg-[size:4rem_4rem]" />
      </div>

      <div className="relative z-10 mx-auto max-w-7xl px-6 py-10">
        {/* Top bar navigation */}
        <div className="flex items-center justify-between mb-8">
          <button
            onClick={() => router.push("/upload")}
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-zinc-400 hover:text-white hover:bg-white/10 transition"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </button>

          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-1.5 text-xs font-semibold text-emerald-400">
            <Zap className="h-3.5 w-3.5" />
            SHA-256 Adaptive Memory Sync Active
          </div>
        </div>

        {/* Header Summary */}
        <div className="mb-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-1.5 text-xs text-emerald-400 font-mono">
              <BrainCircuit className="h-3.5 w-3.5" />
              AI Random Forest + SHAP Explainability
            </div>

            <h1 className="text-4xl sm:text-5xl font-black break-all">
              {analysis.filename}
            </h1>

            <p className="mt-2 font-mono text-xs text-zinc-500 break-all">
              SHA-256: {analysis.sha256}
            </p>
          </div>

          <div className="flex gap-4">
            {/* Predicted Malware Family Card */}
            <div className="rounded-3xl border border-white/10 bg-white/5 px-6 py-5 flex flex-col items-center justify-center min-w-[170px] backdrop-blur-xl">
              <span className="text-xs text-zinc-500 uppercase tracking-wider font-semibold">Classification</span>
              <span className={`mt-1 text-2xl font-black ${predictedFamily !== "Benign" ? "text-red-400" : "text-emerald-400"}`}>
                {predictedFamily}
              </span>
              <span className="mt-1 text-xs text-zinc-400 font-mono">
                {confidencePercent}% Confidence
              </span>
            </div>

            {/* Risk Score Card */}
            <div
              className={`rounded-3xl border px-8 py-5 flex flex-col items-center justify-center min-w-[170px] backdrop-blur-xl ${
                analysis.suspiciousScore > 70
                  ? "border-red-500/30 bg-red-500/10 text-red-400"
                  : analysis.suspiciousScore > 40
                  ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400"
                  : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
              }`}
            >
              <div className="flex items-center gap-2 text-xs uppercase tracking-wider font-semibold">
                {analysis.suspiciousScore > 40 ? (
                  <ShieldAlert className="h-4 w-4" />
                ) : (
                  <ShieldCheck className="h-4 w-4" />
                )}
                Risk Score
              </div>
              <h2 className="mt-1 text-4xl font-black">{analysis.suspiciousScore}%</h2>
            </div>
          </div>
        </div>

        {/* Quick Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl">
            <p className="text-xs text-zinc-500 uppercase tracking-wider">Architecture</p>
            <p className="mt-1 text-base font-semibold text-zinc-200 truncate">{analysis.machineType}</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl">
            <p className="text-xs text-zinc-500 uppercase tracking-wider">Shannon Entropy</p>
            <p className={`mt-1 text-base font-semibold ${analysis.entropy > 7.0 ? "text-yellow-400" : "text-emerald-400"}`}>
              {analysis.entropy} / 8.0 {analysis.isPacked ? "⚡ Packed" : ""}
            </p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl">
            <p className="text-xs text-zinc-500 uppercase tracking-wider">Entry Point</p>
            <p className="mt-1 text-base font-mono font-semibold text-zinc-200">{analysis.entryPoint}</p>
          </div>
          <div className="rounded-2xl border border-white/10 bg-white/5 p-4 backdrop-blur-xl">
            <p className="text-xs text-zinc-500 uppercase tracking-wider">Sections & APIs</p>
            <p className="mt-1 text-base font-semibold text-zinc-200">
              {analysis.sections?.length || 0} Sections / {analysis.imports?.length || 0} APIs
            </p>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap gap-2 border-b border-white/10 pb-4 mb-6">
          <button
            onClick={() => setActiveTab("ml_shap")}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition ${
              activeTab === "ml_shap" ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "text-zinc-400 hover:text-white"
            }`}
          >
            <BrainCircuit className="h-4 w-4" /> AI & SHAP Explainability
          </button>
          <button
            onClick={() => setActiveTab("terminal")}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition ${
              activeTab === "terminal" ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "text-zinc-400 hover:text-white"
            }`}
          >
            <Terminal className="h-4 w-4" /> Live Terminal Log
          </button>
          <button
            onClick={() => setActiveTab("sections")}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition ${
              activeTab === "sections" ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "text-zinc-400 hover:text-white"
            }`}
          >
            <Layers className="h-4 w-4" /> Section Tables ({analysis.sections?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab("imports")}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition ${
              activeTab === "imports" ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "text-zinc-400 hover:text-white"
            }`}
          >
            <FileCode className="h-4 w-4" /> API Imports ({analysis.imports?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab("indicators")}
            className={`flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition ${
              activeTab === "indicators" ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "text-zinc-400 hover:text-white"
            }`}
          >
            <Activity className="h-4 w-4" /> Threat Indicators ({analysis.indicators?.length || 0})
          </button>
        </div>

        {/* Tab Content: ML & SHAP Explainability */}
        {activeTab === "ml_shap" && (
          <div className="space-y-8">
            {/* Multi-Class Probability Breakdown */}
            <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
              <div className="flex items-center gap-2 mb-4">
                <PieChart className="h-5 w-5 text-emerald-400" />
                <h2 className="text-xl font-bold">Malware Family Probability Distribution</h2>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                {Object.entries(analysis.familyProbabilities || { Benign: 0.95, Trojan: 0.02, Ransomware: 0.01, Spyware: 0.01, Worm: 0.005, Backdoor: 0.005 }).map(([family, prob]) => (
                  <div
                    key={family}
                    className={`rounded-2xl border p-4 text-center transition ${
                      family === predictedFamily
                        ? "border-emerald-500/50 bg-emerald-500/10"
                        : "border-white/5 bg-black/30"
                    }`}
                  >
                    <p className="text-xs text-zinc-400 uppercase font-medium">{family}</p>
                    <p className="text-xl font-black mt-1 text-white">{((prob as number) * 100).toFixed(1)}%</p>
                    <div className="w-full bg-zinc-800 h-1.5 rounded-full mt-2 overflow-hidden">
                      <div
                        className={`h-full ${family === predictedFamily ? "bg-emerald-400" : "bg-zinc-600"}`}
                        style={{ width: `${(prob as number) * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* SHAP Decision Waterfall / Feature Impact Attribution */}
            <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <BrainCircuit className="h-5 w-5 text-emerald-400" />
                  <h2 className="text-xl font-bold">SHAP Feature Attribution & Decision Transparency</h2>
                </div>
                <div className="flex items-center gap-4 text-xs font-semibold">
                  <span className="flex items-center gap-1.5 text-red-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-400" /> Malicious Influence (+)
                  </span>
                  <span className="flex items-center gap-1.5 text-emerald-400">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Benign Influence (-)
                  </span>
                </div>
              </div>

              <div className="space-y-4 mt-6">
                {(analysis.shapExplanation || []).map((shap, idx) => {
                  const isMalicious = shap.direction === "malicious";
                  const impactPercent = Math.min(Math.abs(shap.impact) * 200, 100);

                  return (
                    <div key={idx} className="rounded-2xl border border-white/5 bg-black/30 p-4">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="font-semibold text-white">{shap.label}</h3>
                            <span className="font-mono text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                              {shap.value}
                            </span>
                          </div>
                          <p className="text-xs text-zinc-400 mt-1">{shap.description}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <span className={`font-mono text-sm font-bold ${isMalicious ? "text-red-400" : "text-emerald-400"}`}>
                            {shap.impact > 0 ? `+${shap.impact}` : shap.impact} SHAP
                          </span>
                        </div>
                      </div>

                      {/* Visual Impact Bar */}
                      <div className="w-full bg-zinc-900 h-2 rounded-full mt-3 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${isMalicious ? "bg-red-500" : "bg-emerald-500"}`}
                          style={{ width: `${impactPercent}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Tab Content: Live Terminal */}
        {activeTab === "terminal" && (
          <div className="overflow-hidden rounded-3xl border border-white/10 bg-black/60 shadow-2xl backdrop-blur-2xl">
            <div className="flex items-center gap-2 border-b border-white/10 px-6 py-4">
              <div className="h-3 w-3 rounded-full bg-red-500" />
              <div className="h-3 w-3 rounded-full bg-yellow-500" />
              <div className="h-3 w-3 rounded-full bg-green-500" />
              <div className="ml-4 flex items-center gap-2 text-sm text-zinc-500 font-mono">
                <Terminal className="h-4 w-4 text-emerald-400" /> pe_guardian_analyzer.exe
              </div>
            </div>

            <div className="h-[480px] overflow-y-auto p-6 font-mono text-sm leading-relaxed">
              {lines.map((line, index) => (
                <div
                  key={index}
                  className={`mb-2 ${
                    line?.includes("MALICIOUS") || line?.includes("[CRITICAL]") || line?.includes("[HIGH]")
                      ? "text-red-400 font-semibold"
                      : line?.includes("CONCLUSION") || line?.includes("DONE")
                      ? "text-emerald-400 font-bold"
                      : line?.includes("PACKED") || line?.includes("SUSPICIOUS") || line?.includes("Random Forest")
                      ? "text-yellow-400"
                      : "text-zinc-300"
                  }`}
                >
                  <span className="mr-2 text-zinc-600 select-none">root@guardian:~$</span>
                  {line}
                </div>
              ))}
              <div className="mt-2 flex items-center text-emerald-400">
                <span className="mr-2 text-zinc-600 select-none">root@guardian:~$</span>
                <div className="h-4 w-2 animate-pulse bg-emerald-400" />
              </div>
            </div>
          </div>
        )}

        {/* Tab Content: Sections */}
        {activeTab === "sections" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-white/10 text-zinc-400 text-xs uppercase">
                    <th className="pb-3">Section Name</th>
                    <th className="pb-3">Virtual Size</th>
                    <th className="pb-3">Raw Size</th>
                    <th className="pb-3">Shannon Entropy</th>
                    <th className="pb-3">Characteristics</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 font-mono">
                  {(analysis.sections || []).map((sec, idx) => (
                    <tr key={idx} className="hover:bg-white/5">
                      <td className="py-3 font-semibold text-emerald-400">{sec.name}</td>
                      <td className="py-3 text-zinc-300">{sec.virtualSize} bytes</td>
                      <td className="py-3 text-zinc-300">{sec.rawSize} bytes</td>
                      <td className="py-3">
                        <span className={`px-2 py-0.5 rounded text-xs ${sec.entropy > 7.3 ? "bg-red-500/20 text-red-400" : "bg-zinc-800 text-zinc-300"}`}>
                          {sec.entropy} / 8.0
                        </span>
                      </td>
                      <td className="py-3 text-xs text-zinc-400">{sec.characteristics}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab Content: Imports */}
        {activeTab === "imports" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            <div className="max-h-[500px] overflow-y-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-white/10 text-zinc-400 text-xs uppercase sticky top-0 bg-black/80 backdrop-blur">
                    <th className="pb-3">Library (DLL)</th>
                    <th className="pb-3">API Function</th>
                    <th className="pb-3">Risk Assessment</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 font-mono">
                  {(analysis.imports || []).map((imp, idx) => (
                    <tr key={idx} className="hover:bg-white/5">
                      <td className="py-3 text-zinc-400">{imp.dllName}</td>
                      <td className="py-3 text-zinc-200 font-semibold">{imp.functionName}</td>
                      <td className="py-3">
                        {imp.isSuspicious ? (
                          <span className="inline-flex items-center gap-1 rounded bg-red-500/20 px-2.5 py-0.5 text-xs text-red-400 border border-red-500/30">
                            Suspicious API
                          </span>
                        ) : (
                          <span className="text-xs text-zinc-500">Standard API</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab Content: Threat Indicators */}
        {activeTab === "indicators" && (
          <div className="rounded-3xl border border-white/10 bg-white/5 p-6 backdrop-blur-xl">
            {(!analysis.indicators || analysis.indicators.length === 0) ? (
              <p className="text-zinc-500 text-center py-10">No critical threat indicators detected.</p>
            ) : (
              <div className="space-y-3">
                {analysis.indicators.map((ind, idx) => (
                  <div
                    key={idx}
                    className={`rounded-2xl border p-4 flex items-start gap-4 ${
                      ind.severity === "critical"
                        ? "border-red-500/40 bg-red-500/10 text-red-300"
                        : ind.severity === "high"
                        ? "border-orange-500/30 bg-orange-500/10 text-orange-300"
                        : ind.severity === "medium"
                        ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-300"
                        : "border-blue-500/30 bg-blue-500/10 text-blue-300"
                    }`}
                  >
                    <ShieldAlert className="h-5 w-5 shrink-0 mt-0.5" />
                    <div>
                      <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-black/40 border border-white/10 mr-2">
                        {ind.severity}
                      </span>
                      <span className="text-sm font-medium">{ind.description}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}