// AGT <-> OpenCode V2 compatibility adapter (final).
// Single artifact: .opencode/plugins/agt.js. There is no sibling directory;
// opencode.json points directly at this file and it is the only plugin entry.
import { resolve } from "node:path";
import { Plugin } from "@opencode/plugin";
import {
  checkArbitraryText,
  evaluateOpenCodeTool,
  evaluateOpenCodeToolOutput,
  getPolicyStatus,
  loadPolicy,
} from "@microsoft/agent-governance-opencode/policy";

// Serialize AGT evaluations: the package's audit writer uses a
// per-pid temp name, so two in-flight evaluations from one process
// can race into a spurious fail-closed policy error.
let agtChain = Promise.resolve();
function serialized(task) {
  const run = agtChain.then(task, task);
  agtChain = run.then(() => undefined, () => undefined);
  return run;
}

function resultText(result) {
  if (typeof result?.content === "string") return result.content;
  if (Array.isArray(result?.content)) {
    return result.content
      .filter((part) => part?.type === "text" && typeof part.text === "string")
      .map((part) => part.text)
      .join("\n");
  }
  if (typeof result?.output === "string") return result.output;
  return "";
}

// R05-10: grep's permission resource is the regex, not the search path, so the
// path rule cannot stop a root-wide search. Scrub control-tree lines from the
// result before the model sees them.
const CONTROL_TREE =
  /(^|[\\/])\.opencode([\\/]|$)|(^|[\\/])\.config[\\/]opencode([\\/]|$)|(^|[\\/])\.local[\\/]share[\\/]opencode([\\/]|$)/i;

function scrubControlTree(text) {
  if (typeof text !== "string" || !text) return text;
  return text
    .split(/\r?\n/)
    .filter((line) => !CONTROL_TREE.test(line))
    .join("\n");
}

function scrubResult(result) {
  if (typeof result?.content === "string") {
    result.content = scrubControlTree(result.content);
  } else if (Array.isArray(result?.content)) {
    for (const part of result.content) {
      if (part?.type === "text" && typeof part.text === "string") {
        part.text = scrubControlTree(part.text);
      }
    }
  }
  if (typeof result?.output === "string") {
    result.output = scrubControlTree(result.output);
  }
}

async function redactResult(state, tool, sessionId, result, redactedOutput) {
  if (typeof result.content === "string") {
    result.content = redactedOutput;
  } else if (Array.isArray(result.content)) {
    const next = [];
    for (const part of result.content) {
      if (part?.type === "text" && typeof part.text === "string") {
        const each = await serialized(() => evaluateOpenCodeToolOutput(state, {
          tool,
          output: part.text,
          sessionId,
        }));
        next.push(
          each.redact && typeof each.redactedOutput === "string"
            ? { ...part, text: each.redactedOutput }
            : part,
        );
      } else {
        next.push(part);
      }
    }
    result.content = next;
  }
  if (typeof result.output === "string") {
    result.output = redactedOutput;
  }
}

export default Plugin.define({
  id: "agt.compat.v1",
  async setup(ctx) {
    const projectRoot =
      ctx.location.project?.canonical ??
      ctx.location.project?.directory ??
      ctx.location.directory;
    const policyPath =
      process.env.AGT_OPENCODE_POLICY_PATH ||
      resolve(projectRoot, ".agt", "policy.json");
    const state = await loadPolicy({ policyPath });

    await ctx.tool.hook("execute.before", async (event) => {
      const result = await serialized(() => evaluateOpenCodeTool(state, {
        tool: event.tool,
        args: event.input,
        cwd: ctx.location.directory,
        sessionId: event.sessionID,
      }));
      if (result.effect === "deny") {
        throw new Error(result.reason || `AGT policy denied tool '${event.tool}'.`);
      }
    });

    await ctx.tool.hook("execute.after", async (event) => {
      if (event.status !== "completed") return;
      if (event.tool === "grep" || event.tool === "glob") scrubResult(event.result);
      const output = resultText(event.result);
      if (!output.trim()) return;
      const result = await serialized(() => evaluateOpenCodeToolOutput(state, {
        tool: event.tool,
        output,
        sessionId: event.sessionID,
      }));
      if (!result.redact || typeof result.redactedOutput !== "string") return;
      await redactResult(state, event.tool, event.sessionID, event.result, result.redactedOutput);
    });

    await ctx.tool.transform((editor) => {
      editor.add({
        name: "agt_policy_status",
        description: "Return the active AGT OpenCode governance policy status and source.",
        input: {
          type: "object",
          properties: {},
          required: [],
          additionalProperties: false,
        },
        execute: async () => {
          const status = await getPolicyStatus(state);
          return {
            content: JSON.stringify(
              {
                ...status,
                allowedTools: state.policy.toolPolicies.allowedTools,
                blockedTools: state.policy.toolPolicies.blockedTools,
                reviewTools: state.policy.toolPolicies.reviewTools,
                defaultEffect: state.policy.toolPolicies.defaultEffect,
              },
              null,
              2,
            ),
          };
        },
      });
      editor.add({
        name: "agt_policy_check_text",
        description:
          "Check text against AGT prompt, context-poisoning, and MCP-style threat detectors.",
        input: {
          type: "object",
          properties: {
            text: { type: "string", description: "Text to inspect." },
          },
          required: ["text"],
          additionalProperties: false,
        },
        execute: async (input) => {
          const text = typeof input?.text === "string" ? input.text : "";
          return {
            content: JSON.stringify(
              checkArbitraryText(state, text, "opencode-check"),
              null,
              2,
            ),
          };
        },
      });
    });
  },
});
