import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow local network IP to load Next.js dev resources so the button works
  allowedDevOrigins: ["192.168.7.213"],
  // Playwright uses native binaries — do not bundle it with Webpack
  serverExternalPackages: ["playwright", "playwright-core"],
  experimental: {
    // Allow larger response bodies for screenshot base64 payloads
  },
};

export default nextConfig;
