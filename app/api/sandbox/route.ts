import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import path from "path";

function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function runCaptureScript(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(process.cwd(), "scripts", "capture.js");
    
    // We increase maxBuffer because base-64 image buffers can be several Megabytes
    execFile("node", [scriptPath, url], { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
      if (error) {
        return reject(new Error(stderr || error.message || "Failed to capture screenshot"));
      }
      resolve(stdout);
    });
  });
}

export async function POST(req: NextRequest) {
  let body: { url?: string };

  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const { url } = body;

  if (!url || typeof url !== "string" || !isValidUrl(url)) {
    return NextResponse.json(
      { error: "A valid http/https URL is required." },
      { status: 400 }
    );
  }

  try {
    const rawOutput = await runCaptureScript(url);
    const result = JSON.parse(rawOutput);
    return NextResponse.json(result, { status: 200 });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Unknown error occurred.";
    return NextResponse.json(
      { error: `Failed to capture page: ${message}` },
      { status: 500 }
    );
  }
}
