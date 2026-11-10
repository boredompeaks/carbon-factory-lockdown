// Native-tool authorization wiring (F1).
//
// The decision table is in ../lib/authz-core.js (pure Node, unit-testable). This file
// is the only part that touches the OpenCode V2 plugin API:
//   - the session directory comes from ctx.session.get, never ctx.location;
//   - the gated-call counter is persisted in plugin storage, and a storage
//     failure throws (deny), never silently continues;
//   - shell is denied; `execute` (Code Mode) is allowed only for capability
//     role=orchestrator, because nested tools re-enter this same table and
//     enforce their own permissions. Every other role is denied execute.
import { Plugin } from "@opencode/plugin";
import { createAuthz } from "../lib/authz-core.js";

export default Plugin.define({
  id: "carbon.native-authz.v1",
  async setup(ctx) {
    const authz = createAuthz({
      storage: {
        get: (key) => ctx.storage.get(key),
        set: (key, value) => ctx.storage.set(key, value),
      },
    });

    await ctx.tool.hook("execute.before", async (event) => {
      const session = await ctx.session.get({ sessionID: event.sessionID });
      const decision = await authz.evaluate({
        tool: event.tool,
        input: event.input ?? {},
        sessionID: event.sessionID,
        sessionDir: session.directory,
      });
      if (!decision.allow) {
        throw new Error(decision.reason || `native authz denied '${event.tool}'`);
      }
    });
  },
});
