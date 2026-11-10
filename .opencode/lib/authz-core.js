// Carbon harness authorization core (F1).
//
// Pure logic only: this module imports node builtins and nothing from
// @opencode/*. The OpenCode wiring lives in authz.js so the decision table can
// be unit-tested without a running server.
//
// Fail-closed rules (any doubt => deny):
//   - writes require a session directory that is exactly one mapped lane;
//   - writes require a live capability whose task_branch matches that lane;
//   - every path is realpath'd; realpath failure denies;
//   - the gated-call counter must persist, otherwise the call denies.
//   - session_move may only target a worktree-map.json lane dir; a session
//     already in a lane needs a live capability, a session outside every lane
//     may bootstrap into one (location only, never write) (F5);
//   - Code Mode `execute` is orchestrator-only; nested tools are re-evaluated
//     by this same decision table (F5).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const WRITE_TOOLS = new Set(["edit", "write", "patch"]);
const READ_TOOLS = new Set(["read"]);
const SEARCH_TOOLS = new Set(["glob", "grep"]);
const DENY_TOOLS = new Set([
  "bash",
  "shell",
  "task",
  "multiedit",
  "apply_patch",
  // These can reach the network or execute code and we cannot prove they never
  // touch the filesystem, so native-tool authz denies them outright.
  // `execute` is the one exception and is handled explicitly below: Code Mode
  // may run only for capability role=orchestrator, because every tool invoked
  // from inside it re-enters this same decision table.
  "execute",
  "webfetch",
  "websearch",
]);
// F5: session move is a native `opencode` action, not an MCP registry tool.
// Personas name the action `opencode_session_move`; `session_move` is accepted
// as an alias because the event may carry the bare tool name.
const SESSION_MOVE_TOOLS = new Set(["opencode_session_move", "session_move"]);
const PATH_KEYS = ["path", "filePath", "file_path"];
const TOOL_KEYS = {
  edit: new Set(["path", "filePath", "file_path", "oldString", "newString", "replaceAll"]),
  write: new Set(["path", "filePath", "file_path", "content"]),
  read: new Set(["path", "filePath", "file_path", "offset", "limit"]),
  patch: new Set(["patchText"]),
  glob: new Set(["pattern", "path", "filePath", "file_path", "hidden", "limit"]),
  grep: new Set([
    "pattern",
    "path",
    "filePath",
    "file_path",
    "include",
    "caseSensitive",
    "limit",
    "literal",
  ]),
  skill: new Set(["id"]),
  subagent: new Set(["agent", "description", "prompt", "background", "sessionID"]),
  opencode_session_move: new Set(["directory", "sessionID"]),
  session_move: new Set(["directory", "sessionID"]),
};
const SENSITIVE_DIRS = new Set([
  ".git",
  ".opencode",
  ".agt",
  "secrets",
  "hacker-scratch",
  "audit-scratch",
]);

export function defaultFactoryRoot() {
  if (process.env.CARBON_HARNESS) return path.resolve(process.env.CARBON_HARNESS);
  // .opencode/lib/authz-core.js -> repo root. Resolve symlinks first: a
  // workspace `.opencode` that links into the factory would otherwise root the
  // factory at the link's parent (e.g. backend-worktrees) and every mapped
  // lane, policy file and ledger lookup would miss. Fall back to the
  // unresolved path when realpath fails so the failure stays fail-closed.
  const modulePath = fileURLToPath(import.meta.url);
  let real = modulePath;
  try {
    real = fs.realpathSync(modulePath);
  } catch {
    // keep the unresolved path
  }
  return path.resolve(path.dirname(real), "..", "..");
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function safeReal(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

function inside(root, target) {
  if (!root || !target) return false;
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith(".." + path.sep) && rel !== ".." && !path.isAbsolute(rel));
}

function toPosix(p) {
  return p.split(path.sep).join("/");
}

// Recursive glob matching for capability.scope and persona resources.
// Supports *, **, **/ and ?. Everything else is literal.
export function globToRegExp(glob) {
  const g = String(glob).replace(/\\/g, "/");
  let re = "^";
  for (let i = 0; i < g.length; i += 1) {
    const c = g[i];
    if (c === "*") {
      if (g[i + 1] === "*") {
        i += 1;
        if (g[i + 1] === "/") {
          i += 1;
          re += "(?:.*/)?";
        } else {
          re += ".*";
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if ("+.^$(){}|[]\\".includes(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp(re + "$");
}

export function matchGlob(glob, rel) {
  return globToRegExp(glob).test(toPosix(rel));
}

// The deny classes shared by reads and writes.
export function isSensitive(rel) {
  const parts = toPosix(rel).split("/").filter(Boolean);
  const base = parts[parts.length - 1] || "";
  if (parts.some((p) => SENSITIVE_DIRS.has(p))) return true;
  for (let i = 0; i < parts.length - 1; i += 1) {
    if (parts[i] === "quality" && parts[i + 1] === "ledger") return true;
  }
  if (base === "policy-manifest.json") return true;
  if (/^\.env/.test(base)) return true;
  if (/\.pem$/.test(base) || /\.key$/.test(base)) return true;
  if (parts.some((p) => /schema-fuzz-evidence/i.test(p))) return true;
  // Any fuzz segment plus any seed segment, in either order and at any depth.
  if (parts.some((p) => /fuzz/i.test(p)) && parts.some((p) => /seed/i.test(p))) {
    return true;
  }
  return false;
}

export function normalizeTool(tool) {
  return String(tool || "").toLowerCase();
}

// Registry tool names treat `.` and `_` as equivalent: `git.state` and
// `git_state` are the same tool, and `carbon-builder_` is a server prefix.
export function canonicalToolName(tool) {
  return normalizeTool(tool).replace(/[._]/g, "_");
}

// Server prefixes may use `-` or `_` (OpenCode V2 normalizes actions to
// `carbon_orchestrator_git_state`). Carbon's role segment has no `_`, so the
// tool boundary is unambiguous; Basemind adds an optional `lane[-_]<lane>`
// segment, and a plain `basemind_git` server has no lane at all.
export function stripServerPrefix(tool) {
  return normalizeTool(tool)
    .replace(/^carbon[-_][a-z0-9-]+[._]/, "")
    .replace(/^basemind[-_](?:lane[-_][a-z0-9-]+[._])?/, "");
}

// Basemind is a read-only surface: these verbs are allowed without a lane
// capability because the orchestrator sits at the workspace root.
const BASEMIND_ALLOW = new Set(["git", "graph", "workspace", "code", "memory", "web"]);
const BASEMIND_DENY = new Set(["admin", "agents", "shell"]);

function basemindVerb(tool) {
  const name = normalizeTool(tool);
  if (!/^basemind[-_]/.test(name)) return null;
  return canonicalToolName(stripServerPrefix(name));
}

export function isBasemindTool(tool) {
  const verb = basemindVerb(tool);
  return verb !== null && !BASEMIND_DENY.has(verb) && BASEMIND_ALLOW.has(verb);
}

export function isBasemindDenied(tool) {
  const verb = basemindVerb(tool);
  return verb !== null && BASEMIND_DENY.has(verb);
}

export function isCodeWrite(tool) {
  return canonicalToolName(stripServerPrefix(tool)) === "code_write";
}

export function isWriteTool(tool) {
  return WRITE_TOOLS.has(normalizeTool(tool)) || isCodeWrite(tool);
}

// F5: `opencode.session_move` and `opencode_session_move` normalize to the same
// canonical name, so the alias covers either event spelling.
export function isSessionMoveTool(tool) {
  return SESSION_MOVE_TOOLS.has(canonicalToolName(tool));
}

export function resolveInputPath(sessionDir, inputPath) {
  if (typeof inputPath !== "string" || !inputPath) return null;
  return path.isAbsolute(inputPath) ? inputPath : path.resolve(sessionDir, inputPath);
}

function relSegments(inputPath) {
  if (typeof inputPath !== "string" || !inputPath) return null;
  const segments = inputPath.split(/[\\/]+/).filter((s) => s !== "" && s !== ".");
  if (segments.length === 0) return null;
  if (segments.some((s) => s === "..")) return null;
  return segments;
}

// Resolve a write target that may not exist yet. Walk up to the nearest
// existing ancestor, realpath that ancestor, then append the remaining
// segments. Absolute input is allowed when the resolved result stays inside
// the lane. Any `..` segment, realpath failure, non-directory ancestor, or
// ancestor/final path outside the lane returns null (deny).
export function resolveTarget(sessionDir, inputPath, laneDir) {
  const segments = relSegments(inputPath);
  if (!segments || !laneDir) return null;
  let current = path.isAbsolute(inputPath)
    ? path.resolve(inputPath)
    : path.resolve(sessionDir, ...segments);
  const tail = [];
  for (;;) {
    let exists = true;
    try {
      fs.lstatSync(current);
    } catch (err) {
      if (err?.code !== "ENOENT" && err?.code !== "ENOTDIR") return null;
      exists = false;
    }
    if (!exists) {
      const parent = path.dirname(current);
      if (parent === current) return null;
      tail.unshift(path.basename(current));
      current = parent;
      continue;
    }
    const ancestor = safeReal(current);
    if (!ancestor) return null;
    if (!inside(laneDir, ancestor)) return null;
    if (tail.length > 0) {
      let stat;
      try {
        stat = fs.statSync(ancestor);
      } catch {
        return null;
      }
      if (!stat.isDirectory()) return null;
    }
    const final = tail.length > 0 ? path.resolve(ancestor, ...tail) : ancestor;
    return inside(laneDir, final) ? final : null;
  }
}

// Return every path-bearing field that was actually sent. Mixed values are a
// dual-key smuggling attempt; all present values must agree.
export function pathFields(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { error: "invalid input object" };
  }
  const present = PATH_KEYS.filter(
    (key) => Object.prototype.hasOwnProperty.call(input, key) && input[key] !== undefined,
  );
  if (present.length === 0) return { paths: [] };
  const values = present.map((key) => input[key]);
  if (values.some((value) => typeof value !== "string" || !value)) {
    return { error: "invalid path field" };
  }
  if (new Set(values).size > 1) return { error: "conflicting path fields" };
  return { paths: values };
}

export function pickPath(input) {
  const fields = pathFields(input);
  return fields.error ? null : fields.paths[0] ?? null;
}

export function validateInputKeys(tool, input) {
  const allowed = TOOL_KEYS[tool];
  if (!allowed) return null;
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return `invalid input for ${tool}`;
  }
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) return `unknown key '${key}' for ${tool}`;
  }
  return null;
}

// Hardlinked files alias another name; deny reads and writes to them. This is
// check-then-open, so a TOCTOU race remains outside what JS can close.
export function hardlinkDenied(realPath) {
  let stat;
  try {
    stat = fs.statSync(realPath);
  } catch (err) {
    if (err?.code === "ENOENT") return null;
    return "stat failed";
  }
  if (stat.isFile() && stat.nlink > 1) return "hardlink alias denied";
  return null;
}

// Patch entries keep their kind so only Add File and Move to may target a path
// that does not exist yet. Update/Delete must resolve to an existing file.
export function parsePatchEntries(input) {
  const text =
    typeof input === "string"
      ? input
      : input?.patchText ?? input?.patch ?? input?.content ?? input?.text ?? "";
  if (typeof text !== "string" || !text) return [];
  const out = [];
  const re = /^\*\*\*\s+(Add|Update|Delete)\s+File:\s*(.+?)\s*$/gm;
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ kind: m[1].toLowerCase(), path: m[2].trim() });
  }
  const move = /^\*\*\*\s+Move\s+to:\s*(.+?)\s*$/gm;
  while ((m = move.exec(text)) !== null) {
    out.push({ kind: "move", path: m[1].trim() });
  }
  return out.filter((entry) => entry.path);
}

export function parsePatchPaths(input) {
  return [...new Set(parsePatchEntries(input).map((entry) => entry.path))];
}

export function loadWorktreeMap(factoryRoot) {
  return readJson(path.join(factoryRoot, "files", "policies", "worktree-map.json"));
}

// Distinct real parent dirs of the mapped lane dirs. In production every lane
// lives under one workspace root (backend-worktrees), which is what the
// orchestrator session uses as its cwd.
export function workspaceRootsFromMap(map) {
  const roots = new Set();
  if (!map || typeof map !== "object") return [];
  for (const dir of Object.values(map)) {
    if (typeof dir !== "string" || !dir) continue;
    const real = safeReal(dir);
    if (!real) continue;
    roots.add(path.dirname(real));
  }
  return [...roots];
}

// Registry allowlist: every accepted MCP tool must normalize to a name in
// files/tools/mcp/registry.json. An absent/broken registry yields an empty
// map, so all non-native tools deny.
export function loadRegistryTools(factoryRoot) {
  const doc = readJson(path.join(factoryRoot, "files", "tools", "mcp", "registry.json"));
  const tools = new Map();
  if (!doc || !Array.isArray(doc.tools)) return tools;
  for (const tool of doc.tools) {
    if (!tool || typeof tool.name !== "string" || !tool.name) continue;
    tools.set(canonicalToolName(tool.name), tool.name);
  }
  return tools;
}

export function resolveRegistryTool(registry, tool) {
  if (!registry || registry.size === 0) return null;
  const direct = canonicalToolName(tool);
  if (registry.has(direct)) return direct;
  const stripped = canonicalToolName(stripServerPrefix(tool));
  if (registry.has(stripped)) return stripped;
  return null;
}

// Reverse-map a session directory to its lane branch. Exactly one exact match
// is required; zero or multiple matches return null. The map may be passed in
// so createAuthz loads worktree-map.json only once.
export function reverseLane(sessionDir, factoryRoot, map = loadWorktreeMap(factoryRoot)) {
  if (!map || typeof map !== "object") return null;
  const sessionReal = safeReal(sessionDir);
  if (!sessionReal) return null;
  const matches = [];
  for (const [branch, dir] of Object.entries(map)) {
    if (typeof dir !== "string" || !dir) continue;
    const laneReal = safeReal(dir);
    if (laneReal && laneReal === sessionReal) matches.push(branch);
  }
  return matches.length === 1 ? matches[0] : null;
}

export function laneDirectory(lane, factoryRoot, map = loadWorktreeMap(factoryRoot)) {
  if (!map || typeof lane !== "string") return null;
  const dir = map[lane];
  return typeof dir === "string" ? safeReal(dir) : null;
}

// F5: a session-move target must be an existing mapped lane dir. Absolute
// input must be an existing absolute directory whose realpath is exactly one
// mapped lane dir (relative `..` segments, symlinks that resolve elsewhere,
// files and unmapped dirs return null). Relative input is never path-resolved:
// it is accepted only as an exact worktree-map key (e.g. "lane/a"), then the
// same realpath / mapped-lane checks apply.
export function resolveSessionMoveDir(directory, factoryRoot, map = loadWorktreeMap(factoryRoot)) {
  if (typeof directory !== "string" || !directory) return null;
  let target = directory;
  if (!path.isAbsolute(target)) {
    if (target.includes("\\")) return null;
    const segments = target.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      return null;
    }
    if (!map || typeof map !== "object") return null;
    if (!Object.prototype.hasOwnProperty.call(map, target)) return null;
    const mapped = laneDirectory(target, factoryRoot, map);
    if (!mapped) return null;
    target = mapped;
  } else if (target.split(/[\\/]+/).some((segment) => segment === "..")) {
    return null;
  }
  const real = safeReal(target);
  if (!real) return null;
  let stat;
  try {
    stat = fs.statSync(real);
  } catch {
    return null;
  }
  if (!stat.isDirectory()) return null;
  const lane = reverseLane(real, factoryRoot, map);
  return lane ? { lane, dir: real } : null;
}

function capabilityDir(factoryRoot) {
  return path.join(factoryRoot, "files", "quality", "ledger", "capability");
}

function listCapabilities(factoryRoot) {
  const dir = capabilityDir(factoryRoot);
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const full = path.join(dir, name);
    let stat;
    try {
      stat = fs.statSync(full);
    } catch {
      continue;
    }
    const rec = readJson(full);
    if (rec && typeof rec === "object" && !Array.isArray(rec)) {
      out.push({ record: rec, mtime: stat.mtimeMs });
    }
  }
  return out;
}

// Newest record that is unexpired, bound to this lane, and (when present)
// bound to this session. Missing expires_at is treated as expired.
export function selectCapability({ factoryRoot, lane, sessionID, now }) {
  if (!lane) return null;
  return (
    listCapabilities(factoryRoot)
      .filter(({ record }) => record.task_branch === lane)
      .filter(({ record }) => !record.session_id || record.session_id === sessionID)
      .filter(({ record }) => {
        const t = Date.parse(record.expires_at);
        return Number.isFinite(t) && t > now;
      })
      .sort((a, b) => b.mtime - a.mtime)[0]?.record ?? null
  );
}

function frontmatter(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }
  const trimmed = text.replace(/^\uFEFF/, "");
  if (!trimmed.startsWith("---")) return null;
  const end = trimmed.indexOf("\n---", 3);
  if (end < 0) return null;
  return trimmed.slice(3, end);
}

function parseRule(line) {
  const body = line.trim().replace(/^-\s*\{/, "").replace(/\}\s*$/, "");
  const rule = {};
  for (const part of body.split(",")) {
    const idx = part.indexOf(":");
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part
      .slice(idx + 1)
      .trim()
      .replace(/^["']|["']$/g, "");
    if (key) rule[key] = value;
  }
  return rule;
}

function personaPath(factoryRoot, role) {
  const normalized = role === "hacker-high" || role === "hacker-max" ? "hacker" : role;
  if (!/^[a-z][a-z0-9-]*$/.test(normalized)) return null;
  return path.join(factoryRoot, ".opencode", "agents", `${normalized}.md`);
}

function personaRules(factoryRoot, role) {
  const file = personaPath(factoryRoot, role);
  if (!file) return null;
  const fm = frontmatter(file);
  if (fm === null) return null;
  const rules = [];
  let inPermissions = false;
  for (const line of fm.split(/\r?\n/)) {
    if (/^permissions:\s*$/.test(line)) {
      inPermissions = true;
      continue;
    }
    if (inPermissions && /^\S/.test(line)) {
      inPermissions = false;
      continue;
    }
    if (inPermissions && /^\s*-\s*\{/.test(line)) rules.push(parseRule(line));
  }
  return rules.length ? rules : null;
}

// Ordered rule list, last match wins (same semantics as the harness).
export function roleAllows(factoryRoot, role, action, resource) {
  const rules = personaRules(factoryRoot, role);
  if (!rules) return false;
  let decision;
  for (const rule of rules) {
    if (rule.action !== action) continue;
    if (rule.resource === "*" || matchGlob(rule.resource, resource)) {
      decision = rule.effect;
    }
  }
  return decision === "allow";
}

export function skillAllowed(factoryRoot, role, skillID) {
  return roleAllows(factoryRoot, role, "skill", String(skillID));
}

function normSubagent(name) {
  return name === "hacker-high" || name === "hacker-max" ? "hacker" : name;
}

// INV-7 source: the orchestrator persona's subagent allows. If the persona is
// absent or unparsable this returns null and the caller must deny.
export function subagentAllowed(factoryRoot, target) {
  const rules = personaRules(factoryRoot, "orchestrator");
  if (!rules) return false;
  const allowed = new Set();
  for (const rule of rules) {
    if (rule.action !== "subagent" || rule.effect !== "allow") continue;
    if (!rule.resource || rule.resource === "*") continue;
    allowed.add(normSubagent(rule.resource));
  }
  return allowed.has(normSubagent(String(target)));
}

function deny(reason) {
  return { allow: false, reason };
}

function allow(note) {
  return { allow: true, note };
}

export function createAuthz(options = {}) {
  const factoryRoot = options.factoryRoot
    ? path.resolve(options.factoryRoot)
    : defaultFactoryRoot();
  const storage = options.storage ?? {
    get: async () => {
      throw new Error("no plugin storage configured");
    },
    set: async () => {
      throw new Error("no plugin storage configured");
    },
  };
  const now = options.now ?? (() => Date.now());
  const registry = loadRegistryTools(factoryRoot);
  // worktree-map.json is read once per authz instance. The mapped lanes also
  // give the workspace roots the orchestrator session runs from.
  const worktreeMap = loadWorktreeMap(factoryRoot);
  const workspaceRoots = workspaceRootsFromMap(worktreeMap);

  async function consumeBudget(cap) {
    const limit = cap?.budget?.tool_calls;
    if (!Number.isInteger(limit) || limit < 1) return deny("invalid capability budget");
    if (typeof cap.capability_id !== "string" || !cap.capability_id) {
      return deny("capability_id missing");
    }
    const key = `authz:calls:${cap.capability_id}`;
    let used;
    try {
      used = await storage.get(key);
    } catch (err) {
      return deny(`budget read failed: ${err?.message ?? err}`);
    }
    // A missing key is a fresh counter. Anything stored must be a real
    // non-negative integer; strings/objects/floats/negatives deny.
    if (used === undefined) used = 0;
    if (!Number.isInteger(used) || used < 0) {
      return deny("persisted tool_call counter is not a non-negative integer");
    }
    if (used + 1 > limit) return deny("capability tool_call budget exhausted");
    try {
      await storage.set(key, used + 1);
    } catch (err) {
      return deny(`budget persist failed: ${err?.message ?? err}`);
    }
    return null;
  }

  function checkWritePath(sessionDir, laneDir, cap, inputPath, { allowMissing = false } = {}) {
    let real;
    if (allowMissing) {
      real = resolveTarget(sessionDir, inputPath, laneDir);
      if (!real) return deny(`unsafe or escaping path: ${inputPath}`);
    } else {
      if (!relSegments(inputPath)) return deny(`unsafe path: ${inputPath}`);
      const resolved = resolveInputPath(sessionDir, inputPath);
      if (!resolved) return deny("write path missing");
      real = safeReal(resolved);
      if (!real) return deny(`realpath failed for ${inputPath}`);
    }
    if (!inside(laneDir, real)) return deny(`path escapes lane: ${inputPath}`);
    const rel = toPosix(path.relative(laneDir, real));
    if (isSensitive(rel)) return deny(`sensitive path: ${inputPath}`);
    if (!Array.isArray(cap.scope) || cap.scope.length === 0) {
      return deny("capability scope missing");
    }
    if (!cap.scope.some((glob) => matchGlob(glob, rel))) {
      return deny(`path outside capability scope: ${rel}`);
    }
    const hardlink = hardlinkDenied(real);
    if (hardlink) return deny(`sensitive path: ${hardlink} (${inputPath})`);
    return null;
  }

  function checkReadPath(sessionDir, laneDir, inputPath) {
    const resolved = resolveInputPath(sessionDir, inputPath);
    if (!resolved) return deny("read path missing");
    const real = safeReal(resolved);
    if (!real) return deny(`realpath failed for ${inputPath}`);
    // Read allowlist, most specific first so rel stays lane-relative:
    //   1. the session's own lane;
    //   2. every workspace root (read-only view across lanes, for the
    //      orchestrator session sitting at the workspace root);
    //   3. the factory root itself, so requests/**, phase6-7/** and
    //      files/policies/** are readable. isSensitive still applies.
    const candidates = [];
    if (laneDir) candidates.push(laneDir);
    for (const root of workspaceRoots) candidates.push(root);
    candidates.push(safeReal(factoryRoot) ?? factoryRoot);
    const matched = candidates.find((root) => inside(root, real));
    if (!matched) return deny(`read outside allowlist: ${inputPath}`);
    const rel = toPosix(path.relative(matched, real));
    if (isSensitive(rel)) return deny(`sensitive read: ${inputPath}`);
    const hardlink = hardlinkDenied(real);
    if (hardlink) return deny(`sensitive read: ${hardlink} (${inputPath})`);
    return null;
  }

  async function evaluate({ tool, input = {}, sessionID, sessionDir }) {
    const name = normalizeTool(tool);
    if (!name) return deny("missing tool name");

    const lane = reverseLane(sessionDir, factoryRoot, worktreeMap);
    const laneDir = lane ? laneDirectory(lane, factoryRoot, worktreeMap) : null;

    // F5: a session may move into a lane dir from worktree-map.json. A session
    // that already holds a live capability keeps its binding and may move
    // again; a session already in a lane with no capability may not. A session
    // that is not in any lane yet (orchestrator bootstrap from the workspace
    // root, or a fresh child of a lane) may move into a mapped lane without a
    // capability: this grants location only, since every write still requires
    // a live capability for the target lane.
    if (isSessionMoveTool(name)) {
      const keyError = validateInputKeys("opencode_session_move", input);
      if (keyError) return deny(keyError);
      const target = resolveSessionMoveDir(input?.directory, factoryRoot, worktreeMap);
      if (!target) return deny(`session move target is not a mapped lane: ${input?.directory}`);
      const boundCap =
        (lane ? selectCapability({ factoryRoot, lane, sessionID, now: now() }) : null) ??
        selectCapability({ factoryRoot, lane: target.lane, sessionID, now: now() });
      if (boundCap) {
        if (typeof boundCap.role !== "string" || !boundCap.role) {
          return deny("capability role unknown");
        }
        return allow(`session move to lane ${target.lane} for role ${boundCap.role}`);
      }
      if (lane) {
        return deny(`no unexpired capability for lane ${lane} (move needs one)`);
      }
      return allow(`session move to lane ${target.lane} (bootstrap; writes need a capability)`);
    }

    // F5: Code Mode `execute` is orchestrator-only. Nested tool calls re-enter
    // this decision table with their own input, so nothing is granted here that
    // the same session could not already do directly.
    if (name === "execute") {
      if (!lane || !laneDir) return deny("execute requires a mapped-lane session");
      const cap = selectCapability({ factoryRoot, lane, sessionID, now: now() });
      if (!cap) return deny(`no unexpired capability for lane ${lane}`);
      if (cap.role !== "orchestrator") {
        return deny(`execute requires orchestrator, role is ${cap.role ?? "unknown"}`);
      }
      return allow("execute allowed for orchestrator; nested tools re-checked");
    }

    if (DENY_TOOLS.has(name)) {
      return deny(`${name} is not available under native-tool authz`);
    }
    const registryTool = resolveRegistryTool(registry, name);

    // Basemind tools are absent from registry.json; allow only the read-only
    // verb surface. admin/agents/shell are denied explicitly, and no lane
    // capability is required (the orchestrator is at the workspace root).
    if (isBasemindDenied(name)) {
      return deny(`basemind ${canonicalToolName(stripServerPrefix(name))} is not allowed`);
    }
    if (isBasemindTool(name)) {
      return allow(`basemind read-only tool ${stripServerPrefix(name)}`);
    }

    const nativeWrite = WRITE_TOOLS.has(name);
    const registryWrite = registryTool === "code_write";

    const cap = lane
      ? selectCapability({ factoryRoot, lane, sessionID, now: now() })
      : null;

    if (nativeWrite || registryWrite) {
      const native = nativeWrite;
      if (native) {
        const keyError = validateInputKeys(name, input);
        if (keyError) return deny(keyError);
      }
      if (!lane || !laneDir) return deny("session directory is not a mapped lane");
      if (!cap) return deny(`no unexpired capability for lane ${lane}`);
      if (!cap.budget || typeof cap.budget !== "object") {
        return deny("capability budget missing");
      }
      if (
        Array.isArray(cap.native_tools) &&
        native &&
        !cap.native_tools.includes(name)
      ) {
        return deny(`native tool ${name} not granted by capability`);
      }

      if (native && name === "patch") {
        const entries = parsePatchEntries(input);
        if (entries.length === 0) return deny("patch contains no file paths");
        for (const entry of entries) {
          const allowMissing = entry.kind === "add" || entry.kind === "move";
          const bad = checkWritePath(sessionDir, laneDir, cap, entry.path, { allowMissing });
          if (bad) return bad;
        }
        const budget = await consumeBudget(cap);
        return budget ?? allow("patch paths inside lane and scope");
      }

      const fields = pathFields(input);
      if (fields.error) return deny(fields.error);
      if (fields.paths.length === 0) return deny(`${name} path missing`);
      const allowMissing = name === "write" || registryWrite;
      for (const inputPath of fields.paths) {
        const bad = checkWritePath(sessionDir, laneDir, cap, inputPath, { allowMissing });
        if (bad) return bad;
      }
      const budget = await consumeBudget(cap);
      return budget ?? allow(`${name} inside lane and scope`);
    }

    if (READ_TOOLS.has(name) || name === "list") {
      if (name === "read") {
        const keyError = validateInputKeys(name, input);
        if (keyError) return deny(keyError);
      }
      const fields = pathFields(input);
      if (fields.error) return deny(fields.error);
      const roots = fields.paths.length > 0 ? fields.paths : name === "list" ? ["."] : [];
      if (roots.length === 0) return deny(`${name} path missing`);
      for (const root of roots) {
        const bad = checkReadPath(sessionDir, laneDir, root);
        if (bad) return bad;
      }
      return allow(`${name} inside allowlist`);
    }

    if (SEARCH_TOOLS.has(name)) {
      const keyError = validateInputKeys(name, input);
      if (keyError) return deny(keyError);
      const fields = pathFields(input);
      if (fields.error) return deny(fields.error);
      const roots = fields.paths.length > 0 ? fields.paths : ["."];
      for (const root of roots) {
        const bad = checkReadPath(sessionDir, laneDir, root);
        if (bad) return bad;
      }
      return allow(`${name} root inside allowlist`);
    }

    if (name === "skill") {
      const keyError = validateInputKeys(name, input);
      if (keyError) return deny(keyError);
      if (!cap) return deny("no unexpired capability for skill use");
      if (typeof cap.role !== "string" || !cap.role) return deny("capability role unknown");
      const skillID = input?.id;
      if (typeof skillID !== "string" || !skillID) return deny("skill id missing");
      if (!skillAllowed(factoryRoot, cap.role, skillID)) {
        return deny(`skill ${skillID} not allowed for role ${cap.role}`);
      }
      return allow(`skill ${skillID} allowed for ${cap.role}`);
    }

    if (name === "subagent") {
      const keyError = validateInputKeys(name, input);
      if (keyError) return deny(keyError);
      if (!cap) return deny("no unexpired capability for subagent use");
      if (cap.role !== "orchestrator") {
        return deny(`subagent requires orchestrator, role is ${cap.role ?? "unknown"}`);
      }
      const target = input?.agent;
      if (typeof target !== "string" || !target) return deny("subagent target missing");
      if (!subagentAllowed(factoryRoot, target)) {
        return deny(`subagent target ${target} not allowed by INV-7`);
      }
      return allow(`subagent ${target} allowed by INV-7`);
    }

    if (registryTool) {
      return allow(`registry tool ${registryTool} delegated to AGT`);
    }
    return deny(`unknown tool '${name}' (not native, not in MCP registry)`);
  }

  return { evaluate, factoryRoot };
}
