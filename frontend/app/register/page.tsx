"use client";

import { useState } from "react";

import { useRouter } from "next/navigation";

import Link from "next/link";

import {
  Shield,
  Lock,
  Mail,
  User,
} from "lucide-react";

import api from "@/lib/axios";

export default function RegisterPage() {
  const router = useRouter();

  const [loading, setLoading] =
    useState(false);

  const [formData, setFormData] =
    useState({
      name: "",
      email: "",
      password: "",
    });

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (
    e: React.FormEvent
  ) => {
    e.preventDefault();

    try {
      setLoading(true);

      await api.post(
        "/auth/register",
        formData
      );

      router.push("/login");
    } catch (error: any) {
      console.error(error);

      alert(
        error.response?.data?.message
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-black px-6">
      {/* Background Glow */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,255,170,0.15),transparent_35%)]" />

      {/* Grid */}
      <div className="absolute inset-0 opacity-20">
        <div className="h-full w-full bg-[linear-gradient(to_right,#0f0f0f_1px,transparent_1px),linear-gradient(to_bottom,#0f0f0f_1px,transparent_1px)] bg-[size:4rem_4rem]" />
      </div>

      {/* Register Card */}
      <div className="relative z-10 w-full max-w-md overflow-hidden rounded-3xl border border-white/10 bg-white/5 p-8 shadow-2xl backdrop-blur-2xl">
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center">
          <div className="mb-4 rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-4">
            <Shield className="h-8 w-8 text-emerald-400" />
          </div>

          <h1 className="text-3xl font-black tracking-wide text-white">
            PE GUARDIAN
          </h1>

          <p className="mt-2 text-sm text-zinc-400">
            Create Your Secure Account
          </p>
        </div>

        {/* Form */}
        <form
          onSubmit={handleSubmit}
          className="space-y-5"
        >
          {/* Name */}
          <div>
            <label className="mb-2 block text-sm text-zinc-400">
              Full Name
            </label>

            <div className="flex items-center rounded-2xl border border-white/10 bg-black/30 px-4">
              <User className="h-5 w-5 text-zinc-500" />

              <input
                type="text"
                name="name"
                placeholder="Enter your name"
                className="w-full bg-transparent p-4 text-white outline-none placeholder:text-zinc-600"
                onChange={handleChange}
              />
            </div>
          </div>

          {/* Email */}
          <div>
            <label className="mb-2 block text-sm text-zinc-400">
              Email Address
            </label>

            <div className="flex items-center rounded-2xl border border-white/10 bg-black/30 px-4">
              <Mail className="h-5 w-5 text-zinc-500" />

              <input
                type="email"
                name="email"
                placeholder="Enter your email"
                className="w-full bg-transparent p-4 text-white outline-none placeholder:text-zinc-600"
                onChange={handleChange}
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="mb-2 block text-sm text-zinc-400">
              Password
            </label>

            <div className="flex items-center rounded-2xl border border-white/10 bg-black/30 px-4">
              <Lock className="h-5 w-5 text-zinc-500" />

              <input
                type="password"
                name="password"
                placeholder="Create a password"
                className="w-full bg-transparent p-4 text-white outline-none placeholder:text-zinc-600"
                onChange={handleChange}
              />
            </div>
          </div>

          {/* Button */}
          <button
            disabled={loading}
            className="w-full rounded-2xl bg-emerald-500 py-4 font-semibold text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading
              ? "Creating Account..."
              : "Register"}
          </button>
        </form>

        {/* Footer */}
        <div className="mt-6 text-center text-sm text-zinc-500">
          Already have an account?{" "}
          <Link
            href="/login"
            className="font-medium text-emerald-400 hover:text-emerald-300"
          >
            Login
          </Link>
        </div>

        {/* Bottom Glow */}
        <div className="absolute -bottom-20 left-1/2 h-40 w-40 -translate-x-1/2 rounded-full bg-emerald-500/20 blur-3xl" />
      </div>
    </div>
  );
}