import { spawnSync } from "node:child_process";
import {
  constants, accessSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const app = fileURLToPath(new URL("../", import.meta.url));
const transcript = JSON.parse(readFileSync(join(app, "tests/golden/native-transcript.json"), "utf8"));
const pin = transcript.sourceCommit;
const toolchain = "1.99.1";
const env = { ...process.env };
const tmp = mkdtempSync(join(tmpdir(), "vanian-console-review-"));

function run(command, args, { cwd = app, capture = false, childEnv = env } = {}) {
  const result = spawnSync(command, args, {
    cwd, env: childEnv, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
    stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    if (capture && result.stdout) process.stderr.write(result.stdout);
    throw Error(command + " failed (" + (result.signal || result.status) + ").");
  }
  return result.stdout?.trim() ?? "";
}

function executable(name, path) {
  const absolute = resolve(path);
  try {
    accessSync(absolute, constants.X_OK);
    if (!statSync(absolute).isFile()) throw Error();
  } catch { throw Error(name + " requires an executable regular file: " + absolute); }
  return absolute;
}

function prepareNative() {
  const overrides = {
    OBSERVER_VERIFIER: "aip-observe-verify",
    AIP_EVALUATOR: "aip-execution-assurance",
    SELF_SAMPLE_GENERATOR: "self-sample",
  };
  for (const key of Object.keys(overrides)) {
    if (env[key]) env[key] = executable(key, env[key]);
  }
  if (Object.keys(overrides).every(key => env[key])) {
    console.log("Checking operator-supplied native executables against archived cases from " + pin);
    return;
  }

  const candidate = resolve(env.AIP_CHECKOUT || app);
  const root = run("git", ["-C", candidate, "rev-parse", "--show-toplevel"], { capture: true });
  try { run("git", ["-C", root, "cat-file", "-e", pin + "^{commit}"]); }
  catch { throw Error("AIP checkout " + root + " must contain " + pin + ". Fetch that revision or set AIP_CHECKOUT."); }
  const nativeEnv = { ...env, RUSTUP_TOOLCHAIN: toolchain };
  const rustc = nativeEnv.RUSTC || "rustc", cargo = nativeEnv.CARGO || "cargo";
  for (const command of [rustc, cargo]) {
    const version = run(command, ["--version"], { capture: true, childEnv: nativeEnv });
    if (version.split(" ")[1] !== toolchain) throw Error("Native review requires Rust and Cargo " + toolchain + "; found " + version + ".");
  }

  console.log("Building locked native sources from " + root + " at " + pin);
  const archive = join(tmp, "source.tar");
  const source = join(tmp, "source");
  mkdirSync(source);
  run("git", ["-C", root, "archive", "--format=tar", "--output=" + archive, pin]);
  run("tar", ["-xf", archive, "-C", source]);
  nativeEnv.CARGO_TARGET_DIR = resolve(env.CARGO_TARGET_DIR || join(app, ".sites-runtime", "aip-review-target"));

  const logs = run(cargo, [
    "build", "--locked", "--message-format=json-render-diagnostics",
    "--bin", overrides.OBSERVER_VERIFIER, "--bin", overrides.AIP_EVALUATOR,
  ], { cwd: source, childEnv: nativeEnv, capture: true });
  const artifacts = logs.split("\n").filter(Boolean).map(line => JSON.parse(line))
    .filter(message => message.reason === "compiler-artifact");
  for (const key of ["OBSERVER_VERIFIER", "AIP_EVALUATOR"]) {
    if (!env[key]) {
      const binary = artifacts.find(a => a.target.name === overrides[key] && a.executable)?.executable;
      if (!binary) throw Error("Cargo did not emit " + overrides[key] + ".");
      env[key] = executable(key, binary);
    }
  }
  if (!env.SELF_SAMPLE_GENERATOR) {
    const library = name => {
      const paths = new Set(artifacts.filter(a => a.target.name === name)
        .flatMap(a => a.filenames).filter(f => f.endsWith(".rlib")));
      if (paths.size !== 1) throw Error("Expected one Cargo artifact for " + name + "; found " + paths.size + ".");
      return [...paths][0];
    };
    const observer = library("aip_observe"), json = library("serde_json");
    const sample = join(tmp, "self-sample");
    run(rustc, ["--edition=2021", join(app, "tests/support/observe_self.rs"),
      "-L", "dependency=" + dirname(observer), "--extern", "aip_observe=" + observer,
      "--extern", "serde_json=" + json, "-o", sample], { childEnv: nativeEnv });
    env.SELF_SAMPLE_GENERATOR = executable("SELF_SAMPLE_GENERATOR", sample);
  }
}

function nativeTests() {
  const files = readdirSync(join(app, "tests")).filter(name => name.endsWith(".test.mjs")).sort()
    .map(name => join(app, "tests", name));
  const tap = run(process.execPath, ["--test", "--test-reporter=tap", ...files], { capture: true });
  console.log(tap);
  const summary = Object.fromEntries([...tap.matchAll(/^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/gm)]
    .map(([, key, value]) => [key, Number(value)]));
  if (!(summary.tests >= 24 && summary.pass === summary.tests &&
    ["fail", "cancelled", "skipped", "todo"].every(key => summary[key] === 0))) {
    throw Error("The complete native/adapter suite must pass without skips, pending tests or cancellations.");
  }
  return summary.pass;
}

function uiTests() {
  const path = join(tmp, "playwright.json");
  run(process.execPath, [join(app, "node_modules/@playwright/test/cli.js"), "test",
    "--forbid-only", "--retries=0", "--reporter=line,json"], {
    childEnv: { ...env, PLAYWRIGHT_JSON_OUTPUT_FILE: path },
  });
  const report = JSON.parse(readFileSync(path, "utf8"));
  const cases = [];
  function collect(suite) {
    for (const spec of suite.specs || []) cases.push(...spec.tests);
    for (const child of suite.suites || []) collect(child);
  }
  for (const suite of report.suites) collect(suite);
  if (cases.length < 14 || report.stats.expected !== cases.length || !cases.every(test =>
    test.expectedStatus === "passed" && test.results.length === 1 && test.results[0].status === "passed")) {
    throw Error("Every Playwright case must execute and pass without retries or expected failures.");
  }
  return cases.length;
}

async function verify() {
  if (process.platform !== "linux") throw Error("The native self-process fixture requires Linux and a readable /proc.");
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 22 || (major === 22 && minor < 13)) throw Error("Node 22.13 or later is required.");
  run("openssl", ["version"]);
  env.VANIAN_LIVE_SOURCE = join(app, "src/server/live.ts");
  env.TSX_LOADER = join(app, "node_modules/tsx/dist/loader.mjs");
  if (env.VANIAN_CHROMIUM) env.VANIAN_CHROMIUM = executable("VANIAN_CHROMIUM", env.VANIAN_CHROMIUM);
  try { accessSync(env.TSX_LOADER); }
  catch { throw Error("Install the console's locked development dependencies with npm ci."); }

  const { chromium } = await import("@playwright/test");
  const browser = await chromium.launch({ headless: true, executablePath: env.VANIAN_CHROMIUM });
  await browser.close();
  prepareNative();
  for (const key of ["OBSERVER_VERIFIER", "AIP_EVALUATOR", "SELF_SAMPLE_GENERATOR"]) {
    console.log(key + " SHA-256 " + createHash("sha256").update(readFileSync(env[key])).digest("hex"));
  }

  run("npm", ["run", "typecheck"]);
  run("npm", ["run", "build"]);
  accessSync(join(app, "dist/server/index.js"));
  if (!statSync(join(app, "dist/client")).isDirectory()) throw Error("The client build output is missing.");
  const native = nativeTests(), ui = uiTests();
  console.log("Verification passed. " + native + " native and adapter tests and " + ui + " Playwright tests passed.");
}

try { await verify(); }
catch (error) { console.error("Verification failed. " + error.message); process.exitCode = 1; }
finally { rmSync(tmp, { recursive: true, force: true }); }
