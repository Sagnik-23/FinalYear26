"use client";

import { useEffect, useState } from "react";

import {
  Upload,
  FileSearch,
  Clock3,
  Loader2,
  Terminal,
} from "lucide-react";

import api from "@/lib/axios";

import { useRouter } from "next/navigation";

interface Analysis {
  id: number;

  filename: string;

  sha256: string;

  suspiciousScore: number;

  createdAt: string;
}

export default function UploadPage() {
  const router = useRouter();

  const [file, setFile] =
    useState<File | null>(null);

  const [loading, setLoading] =
    useState(false);

  const [historyLoading, setHistoryLoading] =
    useState(true);

  const [history, setHistory] =
    useState<Analysis[]>([]);

  const [statusText, setStatusText] =
    useState("Analyze File");

  /*
  |--------------------------------------------------------------------------
  | Fetch History
  |--------------------------------------------------------------------------
  */

  const fetchHistory = async () => {
    try {
      const res = await api.get(
        "/analyze/history"
      );

      setHistory(res.data.analyses || []);
    } catch (error) {
      console.error(error);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  /*
  |--------------------------------------------------------------------------
  | Upload File
  |--------------------------------------------------------------------------
  */

  const handleUpload = async () => {
    if (!file) {
      return alert(
        "Please select an EXE file"
      );
    }

    try {
      setLoading(true);

      /*
      |--------------------------------------------------------------------------
      | Fake Terminal Status Animation
      |--------------------------------------------------------------------------
      */

      setStatusText(
        "Uploading Executable..."
      );

      setTimeout(() => {
        setStatusText(
          "Parsing PE Headers..."
        );
      }, 700);

      setTimeout(() => {
        setStatusText(
          "Analyzing Imports..."
        );
      }, 1400);

      setTimeout(() => {
        setStatusText(
          "Calculating Entropy..."
        );
      }, 2100);

      setTimeout(() => {
        setStatusText(
          "Generating Report..."
        );
      }, 2800);

      const formData =
        new FormData();

      formData.append("file", file);

      const res = await api.post(
        "/analyze/upload",
        formData,
        {
          headers: {
            "Content-Type":
              "multipart/form-data",
          },
        }
      );

      /*
      |--------------------------------------------------------------------------
      | Redirect To Analysis Page
      |--------------------------------------------------------------------------
      */

      setTimeout(() => {
        router.push(
          `/analysis/${res.data.analysisId}`
        );
      }, 3500);
    } catch (error: any) {
      console.error(error);

      alert(
        error.response?.data?.message
      );

      setLoading(false);

      setStatusText("Analyze File");
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-black text-white">
      {/* Background Glow */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,255,170,0.15),transparent_35%)]" />

      {/* Grid */}
      <div className="absolute inset-0 opacity-20">
        <div className="h-full w-full bg-[linear-gradient(to_right,#0f0f0f_1px,transparent_1px),linear-gradient(to_bottom,#0f0f0f_1px,transparent_1px)] bg-[size:4rem_4rem]" />
      </div>

      <div className="relative z-10 mx-auto max-w-7xl px-6 py-14">
        {/* Header */}
        <div className="mb-12">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-400">
            <Terminal className="h-4 w-4" />
            PE Guardian Analysis Engine
          </div>

          <h1 className="text-5xl font-black tracking-tight">
            Malware Analysis Dashboard
          </h1>

          <p className="mt-4 max-w-2xl text-lg leading-8 text-zinc-400">
            Upload Windows executables and
            inspect PE headers, suspicious
            imports, entropy levels, and
            malware indicators through an
            advanced cybersecurity analysis
            pipeline.
          </p>
        </div>

        {/* Layout */}
        <div className="grid gap-8 lg:grid-cols-3">
          {/* Upload Card */}
          <div className="lg:col-span-1">
            <div className="rounded-3xl border border-white/10 bg-white/5 p-8 backdrop-blur-2xl">
              {/* Header */}
              <div className="mb-6 flex items-center gap-4">
                <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-4">
                  <Upload className="h-7 w-7 text-emerald-400" />
                </div>

                <div>
                  <h2 className="text-2xl font-bold">
                    Upload EXE
                  </h2>

                  <p className="text-sm text-zinc-500">
                    Analyze executable files
                  </p>
                </div>
              </div>

              {/* Upload Box */}
              <label className="group flex h-64 cursor-pointer flex-col items-center justify-center rounded-3xl border-2 border-dashed border-white/10 bg-black/20 transition duration-300 hover:border-emerald-500/40 hover:bg-emerald-500/5">
                <Upload className="mb-4 h-14 w-14 text-zinc-600 transition group-hover:scale-110 group-hover:text-emerald-400" />

                <p className="text-center text-lg text-zinc-300">
                  Drag & drop EXE here
                </p>

                <p className="mt-2 text-sm text-zinc-500">
                  or click to browse
                </p>

                <input
                  type="file"
                  accept=".exe"
                  className="hidden"
                  onChange={(e) =>
                    setFile(
                      e.target.files?.[0] ||
                        null
                    )
                  }
                />
              </label>

              {/* File Info */}
              {file && (
                <div className="mt-5 rounded-2xl border border-white/10 bg-black/30 p-5">
                  <div className="flex items-center gap-3">
                    <FileSearch className="h-6 w-6 text-emerald-400" />

                    <div>
                      <p className="font-medium text-white">
                        {file.name}
                      </p>

                      <p className="mt-1 text-sm text-zinc-500">
                        {(
                          file.size /
                          1024 /
                          1024
                        ).toFixed(2)}{" "}
                        MB
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Upload Button */}
              <button
                onClick={handleUpload}
                disabled={loading}
                className="mt-6 flex w-full items-center justify-center gap-3 rounded-2xl bg-emerald-500 py-4 font-semibold text-black transition duration-300 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin" />

                    {statusText}
                  </>
                ) : (
                  <>
                    <Terminal className="h-5 w-5" />

                    Analyze File
                  </>
                )}
              </button>

              {/* Mini Terminal */}
              {loading && (
                <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-black/60">
                  <div className="flex items-center gap-2 border-b border-white/10 px-4 py-3">
                    <div className="h-3 w-3 rounded-full bg-red-500" />
                    <div className="h-3 w-3 rounded-full bg-yellow-500" />
                    <div className="h-3 w-3 rounded-full bg-green-500" />

                    <span className="ml-3 text-xs text-zinc-500">
                      analysis_terminal.exe
                    </span>
                  </div>

                  <div className="space-y-2 p-4 font-mono text-sm">
                    <p className="text-emerald-400">
                      root@guardian:~$ {statusText}
                    </p>

                    <div className="flex items-center">
                      <span className="mr-2 text-zinc-600">
                        root@guardian:~$
                      </span>

                      <div className="h-4 w-2 animate-pulse bg-emerald-400" />
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* History */}
          <div className="lg:col-span-2">
            <div className="rounded-3xl border border-white/10 bg-white/5 p-8 backdrop-blur-2xl">
              {/* Header */}
              <div className="mb-8 flex items-center justify-between">
                <div>
                  <h2 className="text-3xl font-bold">
                    Previous Analyses
                  </h2>

                  <p className="mt-2 text-zinc-500">
                    Access your previously
                    scanned executables
                  </p>
                </div>

                <Clock3 className="h-8 w-8 text-zinc-600" />
              </div>

              {/* Loading */}
              {historyLoading ? (
                <div className="flex justify-center py-20">
                  <Loader2 className="h-10 w-10 animate-spin text-emerald-400" />
                </div>
              ) : history.length === 0 ? (
                /* Empty */
                <div className="flex h-72 flex-col items-center justify-center rounded-3xl border border-dashed border-white/10 bg-black/20">
                  <FileSearch className="mb-5 h-14 w-14 text-zinc-700" />

                  <p className="text-lg text-zinc-400">
                    No analyses found
                  </p>

                  <p className="mt-2 text-sm text-zinc-600">
                    Upload your first executable
                  </p>
                </div>
              ) : (
                /* History Cards */
                <div className="space-y-4">
                  {history.map((item) => (
                    <div
                      key={item.id}
                      onClick={() =>
                        router.push(
                          `/analysis/${item.id}`
                        )
                      }
                      className="group cursor-pointer rounded-2xl border border-white/10 bg-black/20 p-5 transition duration-300 hover:border-emerald-500/30 hover:bg-white/5"
                    >
                      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
                        {/* Left */}
                        <div>
                          <h3 className="text-lg font-semibold text-white transition group-hover:text-emerald-400">
                            {item.filename}
                          </h3>

                          <p className="mt-2 break-all text-sm text-zinc-500">
                            {item.sha256}
                          </p>
                        </div>

                        {/* Right */}
                        <div className="flex items-center gap-4">
                          {/* Risk */}
                          <div
                            className={`rounded-xl px-4 py-2 text-sm font-semibold ${
                              item.suspiciousScore >
                              70
                                ? "bg-red-500/10 text-red-400"
                                : item.suspiciousScore >
                                  40
                                ? "bg-yellow-500/10 text-yellow-400"
                                : "bg-emerald-500/10 text-emerald-400"
                            }`}
                          >
                            Risk:{" "}
                            {
                              item.suspiciousScore
                            }
                            %
                          </div>

                          {/* Date */}
                          <div className="text-sm text-zinc-500">
                            {new Date(
                              item.createdAt
                            ).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}