// What ships to a Windows node is DERIVED from the agent's import graph (windows/node/deploy-files.mjs), and a gap is a
// loud refusal, never a partial node (coordinator enclave-87, after the relay's named-file deploy crash-looped
// production on 2026-09-25). sync.sh ships exactly that closure.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { closure } from "../windows/node/deploy-files.mjs";

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

test("the real tree's closure is complete and carries every module the hv node runs", () => {
  const { files, problems } = closure();
  assert.deepEqual(problems, []);
  for (const f of ["windows/node/agent.mjs", "windows/node/host.mjs", "windows/node/hvnode-evidence.mjs", "windows/node/isolation-client.mjs",
                   "windows/node/isolation-lifecycle.mjs", "windows/node/host-delegation.mjs", "windows/node/hvcert.mjs", "windows/node/hvnode-attach.mjs", "isolation/m4/guestd/supervisor-guestcert.mjs", "windows/vbslike/datapath/node-bridge.mjs",
                   "windows/vbslike/datapath/datapath.mjs", "isolation/m4/guestd/supervisor-splice.mjs", "windows/node/package.json",
                   "windows/node/session-api-auth.mjs", "windows/node/host-admission.bundle.mjs"])
    assert.ok(files.includes(f), `${f} is not shipped`);
  assert.ok(!files.some((f) => /\.test\.mjs$|\/evidence\//.test(f)), "a test or evidence file would be shipped");
  // the CLI agrees, and exits 0
  const out = execFileSync(process.execPath, [path.join(REPO, "windows/node/deploy-files.mjs")], { encoding: "utf8" }).trim().split("\n");
  assert.deepEqual(out, files);
});

function tree(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ee-deploy-"));
  for (const [p, body] of Object.entries({ "windows/node/package.json": JSON.stringify({ dependencies: { ws: "^8" } }), ...files })) {
    fs.mkdirSync(path.dirname(path.join(root, p)), { recursive: true });
    fs.writeFileSync(path.join(root, p), body);
  }
  return root;
}

test("a missing module, an undeclared package, and a package imported from outside windows/node each REFUSE by name", () => {
  const missing = closure({ root: tree({ "windows/node/agent.mjs": 'import x from "./gone.mjs";\nconst y = await import("../vbslike/lost.mjs");' }), extra: [] });
  assert.ok(missing.problems.some((p) => /gone\.mjs is missing/.test(p)), missing.problems.join(" | "));
  assert.ok(missing.problems.some((p) => /vbslike\/lost\.mjs is missing/.test(p)));
  const undeclared = closure({ root: tree({ "windows/node/agent.mjs": 'import { x } from "viem";' }), extra: [] });
  assert.ok(undeclared.problems.some((p) => /package viem, which windows\/node\/package\.json does not declare/.test(p)));
  const outside = closure({ root: tree({ "windows/node/agent.mjs": 'import "../../lib/a.mjs";', "lib/a.mjs": 'import ws from "ws";' }), extra: [] });
  assert.ok(outside.problems.some((p) => /lib\/a\.mjs imports package ws from outside windows\/node/.test(p)));
  // prose in a comment is not an import
  const prose = closure({ root: tree({ "windows/node/agent.mjs": '// kept separately from "expired"\n/* see from "nothing" */\nexport const u = "https://x";' }), extra: [] });
  assert.deepEqual(prose.problems, []);
});

test("sync.sh ships the derived closure and stops when it is refused; the hand-written list is gone", () => {
  const s = fs.readFileSync(path.join(REPO, "windows/node/sync.sh"), "utf8");
  assert.match(s, /files="\$\(node "\$HERE\/deploy-files\.mjs"\)" \|\| \{ echo "sync\.sh: REFUSED/);
  assert.doesNotMatch(s, /"\$HERE"\/host\.mjs/, "a hand-written file list is back");
});
