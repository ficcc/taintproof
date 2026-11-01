#!/usr/bin/env node
"use strict";

// Installs the skill when run with npx. This is deliberately not a postinstall hook:
// a security tool should only change the machine when someone asks it to.

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PACKAGE_DIR = path.resolve(__dirname, "..");
const SKILL_ITEMS = ["SKILL.md", "references", "scripts"];
const MINIMUM_PYTHON_CHECK = "import sys; raise SystemExit(sys.version_info < (3, 11))";

const HELP = `Usage: npx taintproof

Installs the Taintproof skill for Claude Code and downloads threat intelligence.
Run it again to update. Set CLAUDE_CONFIG_DIR to install outside ~/.claude.`;

function skillDirectory() {
  const configDirectory = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), ".claude");
  return path.join(configDirectory, "skills", "taintproof");
}

function blockingInstall(target) {
  let stats;
  try {
    stats = fs.lstatSync(target);
  } catch {
    return null;
  }
  // Node reports Windows junctions as symbolic links too.
  if (stats.isSymbolicLink()) {
    return `${target} is a link to another folder, so installing would overwrite that folder.`;
  }
  if (fs.existsSync(path.join(target, ".git"))) {
    return `${target} is a git clone. Update it with git pull instead.`;
  }
  return null;
}

function findPython() {
  for (const command of ["python3", "python"]) {
    const result = spawnSync(command, ["-c", MINIMUM_PYTHON_CHECK], { stdio: "ignore" });
    if (result.status === 0) {
      return command;
    }
  }
  return null;
}

function semgrepAvailable() {
  const executable = process.platform === "win32" ? "semgrep.exe" : "semgrep";
  const local = path.join(os.homedir(), ".local", "bin", executable);
  return spawnSync("semgrep", ["--version"], { stdio: "ignore" }).status === 0 || fs.existsSync(local);
}

function main() {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    console.log(HELP);
    return 0;
  }

  const target = skillDirectory();
  const blocked = blockingInstall(target);
  if (blocked) {
    console.error(`Not installed: ${blocked}`);
    return 1;
  }

  // Generated threat data is not in the package, so an update leaves it in place.
  for (const item of SKILL_ITEMS) {
    fs.cpSync(path.join(PACKAGE_DIR, item), path.join(target, item), { recursive: true, force: true });
  }
  console.log(`Installed Taintproof to ${target}`);

  const updateScript = path.join(target, "scripts", "update-threat-intel.py");
  const python = findPython();
  if (python === null) {
    console.error("Python 3.11 or newer was not found. Install it, then run:");
    console.error(`  python3 "${updateScript}"`);
    return 1;
  }

  const update = spawnSync(python, [updateScript], { stdio: "inherit" });
  if (update.status !== 0) {
    const retry = `  ${python} "${updateScript}"`;
    if (!fs.existsSync(path.join(target, "references", "dynamic-rules.md"))) {
      console.error("Threat intelligence did not download, and reviews need it. Try again with:");
      console.error(retry);
      return 1;
    }
    console.log("\nThreat intelligence was not refreshed, so the existing data was kept. To retry:");
    console.log(retry);
  }

  if (!semgrepAvailable()) {
    console.log("\nSemgrep was not found. Reviews still run, but with a weaker search.");
    console.log("Install it with: uv tool install semgrep");
  }
  console.log("\nDone. In Claude Code, run /taintproof or ask for a security review.");
  return 0;
}

process.exitCode = main();
