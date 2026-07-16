import { cp, rm, stat } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const webRoot = path.resolve(process.cwd());
const standaloneRoot = path.join(webRoot, ".next", "standalone");
const serverEntry = path.join(standaloneRoot, "server.js");
const publicSource = path.join(webRoot, "public");
const staticSource = path.join(webRoot, ".next", "static");
const publicTarget = path.join(standaloneRoot, "public");
const staticTarget = path.join(standaloneRoot, ".next", "static");

async function requirePath(target, expectedKind) {
  let metadata;
  try {
    metadata = await stat(target);
  } catch {
    throw new Error(`standalone smoke prerequisite is missing: ${path.relative(webRoot, target)}`);
  }
  const valid = expectedKind === "file" ? metadata.isFile() : metadata.isDirectory();
  if (!valid) {
    throw new Error(
      `standalone smoke prerequisite is not a ${expectedKind}: ${path.relative(webRoot, target)}`,
    );
  }
}

const hostname = process.env.HOSTNAME?.trim();
const port = Number(process.env.PORT);
if (!hostname) throw new Error("HOSTNAME is required for standalone smoke");
if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
  throw new Error("PORT must be an integer between 1 and 65535 for standalone smoke");
}

await Promise.all([
  requirePath(serverEntry, "file"),
  requirePath(publicSource, "directory"),
  requirePath(staticSource, "directory"),
]);
await Promise.all([
  rm(publicTarget, { recursive: true, force: true }),
  rm(staticTarget, { recursive: true, force: true }),
]);
await Promise.all([
  cp(publicSource, publicTarget, { recursive: true, force: true }),
  cp(staticSource, staticTarget, { recursive: true, force: true }),
]);

process.chdir(standaloneRoot);
await import(pathToFileURL(serverEntry).href);
