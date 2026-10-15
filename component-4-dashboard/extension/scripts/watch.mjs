// Runs the webview build (vite --watch) and the extension build (esbuild --watch) side by side.
// Plain Node instead of shell `&` so it works the same on Windows, macOS and Linux.
import { spawn } from "node:child_process";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const jobs = [
  spawn(npm, ["--prefix", "../frontend", "run", "watch"], { stdio: "inherit", shell: process.platform === "win32" }),
  spawn(process.execPath, ["scripts/build.mjs", "--watch"], { stdio: "inherit" }),
];
const stop = () => jobs.forEach((j) => j.kill());
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
jobs.forEach((j) => j.on("exit", (code) => { if (code) { stop(); process.exit(code); } }));
