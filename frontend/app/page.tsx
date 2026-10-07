"use client";

import Link from "next/link";
import {
  Shield,
  Upload,
  FileSearch,
  Lock,
  Activity,
  Database,
} from "lucide-react";

export default function Home() {
  return (
    <div className="min-h-screen bg-black text-white overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,255,170,0.15),transparent_35%)]" />

      <div className="absolute inset-0 opacity-20">
        <div className="h-full w-full bg-[linear-gradient(to_right,#0f0f0f_1px,transparent_1px),linear-gradient(to_bottom,#0f0f0f_1px,transparent_1px)] bg-[size:4rem_4rem]" />
      </div>

      {/* Hero */}
      <section className="relative z-10 mx-auto flex max-w-7xl flex-col items-center px-6 py-28 text-center">
        <div className="mb-6 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-sm text-emerald-400 backdrop-blur-xl">
          AI Powered Portable Executable Analysis
        </div>

        <h1 className="max-w-5xl text-5xl font-black leading-tight tracking-tight sm:text-7xl">
          Detect Suspicious
          <span className="text-emerald-400">
            {" "}
            Windows Executables
          </span>
          <br />
          In Seconds
        </h1>

        <p className="mt-8 max-w-2xl text-lg leading-8 text-zinc-400">
          Upload EXE files and analyze PE headers,
          imports, entropy, suspicious indicators,
          packed binaries, and malware heuristics
          using a modern cybersecurity dashboard.
        </p>

        <div className="mt-10 flex flex-col gap-4 sm:flex-row">
          <Link
            href="/upload"
            className="flex items-center justify-center gap-2 rounded-2xl bg-emerald-500 px-8 py-4 font-semibold text-black transition hover:bg-emerald-400"
          >
            <Upload className="h-5 w-5" />
            Analyze File
          </Link>

          <Link
            href="/dashboard"
            className="rounded-2xl border border-white/10 bg-white/5 px-8 py-4 font-semibold backdrop-blur-xl transition hover:bg-white/10"
          >
            View Dashboard
          </Link>
        </div>

        {/* Cyber Terminal Card */}
        <div className="mt-20 w-full max-w-5xl overflow-hidden rounded-3xl border border-white/10 bg-white/5 shadow-2xl backdrop-blur-2xl">
          <div className="flex items-center gap-2 border-b border-white/10 px-6 py-4">
            <div className="h-3 w-3 rounded-full bg-red-500" />
            <div className="h-3 w-3 rounded-full bg-yellow-500" />
            <div className="h-3 w-3 rounded-full bg-green-500" />

            <span className="ml-4 text-sm text-zinc-500">
              analysis_terminal.exe
            </span>
          </div>

          <div className="space-y-3 p-6 font-mono text-left text-sm">
            <p className="text-emerald-400">
              &gt; Uploading sample.exe...
            </p>

            <p className="text-cyan-400">
              &gt; Parsing PE Header...
            </p>

            <p className="text-zinc-300">
              [+] Sections Detected: .text,
              .data, .rsrc
            </p>

            <p className="text-zinc-300">
              [+] Entropy Score: 7.81
            </p>

            <p className="text-yellow-400">
              [!] Packed Binary Suspected
            </p>

            <p className="text-red-400">
              [!] Suspicious Import:
              WriteProcessMemory
            </p>

            <p className="text-emerald-400">
              [+] Risk Score: 84/100
            </p>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="relative z-10 mx-auto max-w-7xl px-6 pb-32">
        <div className="mb-14 text-center">
          <h2 className="text-4xl font-bold">
            Advanced Malware Intelligence
          </h2>

          <p className="mt-4 text-zinc-400">
            Built for cybersecurity research and
            malware analysis workflows.
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
          {features.map((feature) => (
            <div
              key={feature.title}
              className="group rounded-3xl border border-white/10 bg-white/5 p-8 backdrop-blur-xl transition hover:border-emerald-500/30 hover:bg-white/10"
            >
              <div className="mb-6 inline-flex rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4 text-emerald-400">
                <feature.icon className="h-6 w-6" />
              </div>

              <h3 className="mb-3 text-xl font-semibold">
                {feature.title}
              </h3>

              <p className="leading-7 text-zinc-400">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

const features = [
  {
    title: "PE Header Parsing",
    description:
      "Extract DOS headers, NT headers, optional headers, and section tables from executables.",
    icon: FileSearch,
  },
  {
    title: "Malware Indicators",
    description:
      "Detect suspicious imports, packed binaries, RWX sections, and entropy anomalies.",
    icon: Activity,
  },
  {
    title: "Secure Uploads",
    description:
      "Protected upload system with JWT authentication and secure backend validation.",
    icon: Lock,
  },
  {
    title: "Analysis History",
    description:
      "Track previous analyses and review uploaded executables from your dashboard.",
    icon: Database,
  },
];