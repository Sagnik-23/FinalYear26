"use client";

import Link from "next/link";

import { Shield } from "lucide-react";

import { useAuth } from "@/context/AuthContext";

export default function Navbar() {
  const { user, logout } = useAuth();

  return (
    <nav className="sticky top-0 z-50 border-b border-white/10 bg-black/60 backdrop-blur-2xl">
      <div className="mx-auto flex h-20 max-w-7xl items-center justify-between px-6">
        {/* Logo */}
        <Link
          href="/"
          className="flex items-center gap-3"
        >
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-2">
            <Shield className="h-5 w-5 text-emerald-400" />
          </div>

          <div>
            <h1 className="text-lg font-black tracking-wider text-white">
              PE GUARDIAN
            </h1>

            <p className="text-xs text-zinc-500">
              Malware Analysis Platform
            </p>
          </div>
        </Link>

        {/* Navigation */}
        <div className="flex items-center gap-6">
          <Link
            href="/dashboard"
            className="text-sm text-zinc-400 transition hover:text-white"
          >
            Dashboard
          </Link>

          <Link
            href="/upload"
            className="text-sm text-zinc-400 transition hover:text-white"
          >
            Upload
          </Link>

          {user ? (
            <div className="flex items-center gap-4">
              <div className="hidden text-right sm:block">
                <p className="text-sm font-medium text-white">
                  {user.name}
                </p>

                <p className="text-xs text-zinc-500">
                  {user.email}
                </p>
              </div>

              <button
                onClick={logout}
                className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-2 text-sm text-red-400 transition hover:bg-red-500 hover:text-white"
              >
                Logout
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <Link
                href="/login"
                className="text-sm text-zinc-400 transition hover:text-white"
              >
                Login
              </Link>

              <Link
                href="/register"
                className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-5 py-2 text-sm font-medium text-emerald-400 transition hover:bg-emerald-500 hover:text-black"
              >
                Register
              </Link>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}