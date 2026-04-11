# ☣️ CIVIXSHIELD-SANDBOX

![CivixShield Header](https://img.shields.io/badge/SECURITY-CRITICAL-red?style=for-the-badge)
![Next.js](https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js)
![Playwright](https://img.shields.io/badge/Playwright-Headless-green?style=for-the-badge&logo=playwright)

**CIVIXSHIELD-SANDBOX** is an advanced, intelligent phishing detection system designed to safely analyze suspicious URLs within an isolated headless Chromium environment. It uses a custom heuristic engine to expose threat vectors without risking your local machine or identity.

---

## 🚀 Key Features

### 🧠 Intelligent Detection Engine
- **Heuristic Analysis**: Detects login forms, credential harvesting patterns, and social engineering triggers.
- **Trusted Brand Whitelist**: Automatically recognizes valid domains (Google, SBI, Microsoft, etc.) while flagging typosquatting (e.g., `amaz0n.xyz`).
- **DOM Inspection**: Scans for hidden inputs, excessive scripts, and manipulative urgency language.
- **Protocol Validation**: Enforces HTTPS checks and flags insecure connections.

### 🎨 Cyberpunk HUD (UI)
- **Real-time Scanning**: Watch the sandbox initialize, render, and analyze threats in a futuristic terminal interface.
- **Risk Telemetry**: 1-100 threat scoring with a dynamic, color-coded risk meter (LOW, MEDIUM, HIGH).
- **Snapshot Isolation**: View high-resolution screenshots of the target site safely contained within the sandbox.

### 🚨 Direct Response
- **One-Click Reporting**: Flag malicious sites for further investigation.
- **Automatic Alerts**: High-risk sites trigger immediate visual warnings and recommended actions.

---

## 🛠 Tech Stack

- **Frontend**: Next.js (App Router), React, CSS Modules.
- **Backend**: Next.js API Routes, Node.js `child_process`.
- **Sandbox**: Playwright (Headless Chromium).
- **Theming**: Custom Neon Cyberpunk CSS.

---

## 📥 Getting Started

### Prerequisites
- Node.js 18+
- Playwright Browser binaries

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/ShriyanshPandey-702/CIVIXSHIELD-SANDBOX.git
   cd CIVIXSHIELD-SANDBOX
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Install Playwright Browsers**
   ```bash
   npx playwright install chromium --with-deps
   ```

4. **Run the development server**
   ```bash
   npm run dev
   ```

Open [http://localhost:3000/sandbox](http://localhost:3000/sandbox) to access the HUD.

---

## 🐳 Docker Deployment (Recommended)

To ensure the sandbox has all necessary Linux dependencies, use the provided Docker instructions in the `deployment_guide.md`.

```bash
docker build -t civixshield-sandbox .
docker run -p 3000:3000 civixshield-sandbox
```

---

## 🛡️ Security Disclaimer
This tool is intended for analysis and educational purposes. While the sandbox provides isolation, always follow best practices when interacting with potentially malicious content.

---

## 📜 License
MIT © [Shriyansh Pandey](https://github.com/ShriyanshPandey-702)
