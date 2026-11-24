function analyzeThreatEngine(rawText) {
  const t = String(rawText || "").trim();
  const low = t.toLowerCase();
  let score = 0;
  const flags = [];
  const signals = [];

  const add = (pts, label, sig) => {
    score += pts;
    if (!flags.includes(label)) flags.push(label);
    if (sig && !signals.includes(sig)) signals.push(sig);
  };

  const urgMatch = low.match(/\b(urgent|immediately|act now|final notice|last warning|within \d+\s*(sec|secs|second|seconds|min|mins|minute|minutes|hr|hrs|hour|hours)|expires?|suspended|locked|disabled|terminated|closed)\b/i);
  if (urgMatch) add(30, "Urgency & Account Threat Pressure", urgMatch[0]);

  const credMatch = low.match(/\b(click here|tap here|verify\s*(your)?\s*(account|identity|token|details)?|reset\s*(your)?\s*password|confirm\s*(your)?\s*(account|card|bank)|update\s*(kyc|details|billing))\b/i);
  if (credMatch) add(28, "Credential Harvesting / Action Call", credMatch[0]);

  const linkMatch = low.match(/(https?:\/\/[^\s]+|www\.[^\s]+|bit\.ly\/[^\s]+|tinyurl\.com\/[^\s]+)\b/i);
  if (linkMatch) add(26, "Suspicious Link or Spoofed Domain Pattern", linkMatch[0]);

  const secMatch = low.match(/\b(otp|pin|cvv|debit\s*card|credit\s*card|bank\s*account|routing\s*number|social\s*security|ssn|seed\s*phrase|private\s*key)\b/i);
  if (secMatch) add(32, "Sensitive Secret / Financial Data Request", secMatch[0]);

  const level = score >= 50 ? "HIGH RISK" : score >= 25 ? "MEDIUM RISK" : "LOW RISK";
  const detail = flags.length ? flags.join(", ") : "No urgent phishing patterns found";
  const summary =
    score >= 50
      ? "High likelihood of phishing attempt. Do not click links or share credentials."
      : "Message appears relatively safe, still verify sender if unexpected.";

  return "Risk: " + level + " (" + score + "/100)\nIndicators: " + detail + "\nSummary: " + summary;
}

import { initializeApp } from "firebase/app";
import { getAI, getGenerativeModel, GoogleAIBackend } from "firebase/ai";

const app = initializeApp({
  apiKey: "YOUR_FIREBASE_API_KEY",
  authDomain: "hybridguard-ai.firebaseapp.com",
  projectId: "hybridguard-ai",
  storageBucket: "hybridguard-ai.firebasestorage.app",
  messagingSenderId: "740306357828",
  appId: "1:740306357828:web:d2e5472f653e87fd36b611",
  measurementId: "G-CY1VBFBLTV"
});

const cloudModel = getGenerativeModel(getAI(app), {
  backend: new GoogleAIBackend(),
  model: "gemini-flash-latest"
});

const $ = (id) => document.getElementById(id);

const SYS =
  "You are HybridGuard AI, a security and scam analyzer. Return: 1) Risk Level (LOW, MEDIUM, or HIGH) with 0-100 score, 2) Key indicators/red flags, 3) Recommended action. Be concise and structured.";

async function runNano(t) {
  if (!("LanguageModel" in window)) {
    throw new Error("LanguageModel unavailable");
  }
  const av = await window.LanguageModel.availability();
  if (av !== "available" && av !== "downloadable") {
    throw new Error("Nano status: " + av);
  }
  const s = await window.LanguageModel.create({
    initialPrompts: [{ role: "system", content: SYS }]
  });
  const r = await s.prompt(t);
  s.destroy();
  return r;
}

async function runCloud(t) {
  const res = analyzeThreatEngine(t);
  const k = "YOUR_GEMINI_API_KEY";
  const models = ["gemini-flash-latest", "gemini-3.8-flash", "gemini-2.5-flash"];

  for (const mdl of models) {
    try {
      const u =
        "[https://generativelanguage.googleapis.com/v1beta/models/](https://generativelanguage.googleapis.com/v1beta/models/)" +
        mdl +
        ":generateContent?key=" +
        encodeURIComponent(k);
      const r = await fetch(u, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: SYS + "\n\nInput:\n" + t + "\n\nRuleSignal:\n" + res }] }]
        })
      });
      if (r.ok) {
        const d = await r.json();
        const aitxt = d.candidates?.[0]?.content?.parts?.[0]?.text || "";
        if (aitxt) return aitxt;
      }
    } catch (e) {}
  }
  return res;
}