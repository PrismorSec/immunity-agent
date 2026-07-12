"use strict";
/**
 * Tests for the Vercel AI SDK adapter. No live eval-server — global fetch is
 * stubbed so these run standalone. Covers:
 *  - failMode semantics: enforce fails CLOSED by default when the eval-server
 *    is unavailable (a suspended user must stay suspended), observe fails open,
 *    and failMode overrides either default. Supersedes the fail-open contract
 *    from PrismorSec/prismor#136, which observe mode keeps.
 *  - useSubject(): ambient per-request attribution, explicit-option precedence,
 *    PRISMOR_SUBJECT fallback, and no bleed across concurrent requests.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { prismorTools, prismorTool, useSubject, PrismorBlocked } = require("../dist/index.js");

function withMockFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve(fn()).finally(() => {
    globalThis.fetch = original;
  });
}

const ALLOW = { allow: true, reason: null, findings: [], blocking: null, subject: null };

/** Mock fetch that records each request body and allows everything. */
function recordingFetch(requests) {
  return async (_url, init) => {
    requests.push({ body: JSON.parse(init.body), headers: init.headers });
    return { ok: true, json: async () => ALLOW };
  };
}

test("allows the call when the eval-server returns allow: true", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ALLOW }),
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell });
      const result = await tools.run_shell.execute({ command: "echo hi" });
      assert.equal(result, "ran: echo hi");
    },
  );
});

test("throws PrismorBlocked when the eval-server denies the call", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ({ allow: false, reason: "blocked for testing", findings: [], blocking: null, subject: null }) }),
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "rm -rf /" }),
        PrismorBlocked,
      );
    },
  );
});

// ── failMode ────────────────────────────────────────────────────────────────

test("enforce mode fails CLOSED on a non-2xx response by default", async () => {
  await withMockFetch(
    async () => ({ ok: false, status: 503 }),
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "rm -rf /" }),
        PrismorBlocked,
      );
    },
  );
});

test("enforce mode fails CLOSED when fetch itself rejects by default", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "rm -rf /" }),
        PrismorBlocked,
      );
    },
  );
});

test("observe mode fails open when the eval-server is unreachable — #136 contract", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell }, { mode: "observe" });
      const result = await tools.run_shell.execute({ command: "rm -rf /" });
      assert.equal(result, "ran: rm -rf /");
    },
  );
});

test("failMode: 'open' overrides the enforce-mode default", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell }, { failMode: "open" });
      const result = await tools.run_shell.execute({ command: "echo hi" });
      assert.equal(result, "ran: echo hi");
    },
  );
});

test("failMode: 'closed' overrides the observe-mode default", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell }, { mode: "observe", failMode: "closed" });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "echo hi" }),
        PrismorBlocked,
      );
    },
  );
});

test("a hung eval-server times out and follows failMode", async () => {
  await withMockFetch(
    (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason));
      }),
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell }, { timeoutMs: 30 });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "echo hi" }),
        PrismorBlocked,
      );
    },
  );
});

// ── useSubject / subject resolution ─────────────────────────────────────────

test("useSubject() attributes calls made inside its scope", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async ({ command }) => `ran: ${command}` };
    const tools = prismorTools({ run_shell });
    await useSubject("user:alice", () => tools.run_shell.execute({ command: "echo hi" }));
    assert.equal(requests.length, 1);
    assert.equal(requests[0].body.subject, "user:alice");
    assert.equal(requests[0].headers["X-Prismor-Subject"], "user:alice");
  });
});

test("subject is resolved per call, not at wrap time", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell }); // wrapped once, outside any subject
    await useSubject("user:alice", () => tools.run_shell.execute({ command: "a" }));
    await useSubject("user:bob", () => tools.run_shell.execute({ command: "b" }));
    assert.deepEqual(
      requests.map((r) => r.body.subject),
      ["user:alice", "user:bob"],
    );
  });
});

test("explicit subject option takes precedence over useSubject()", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell }, { subject: "user:pinned" });
    await useSubject("user:alice", () => tools.run_shell.execute({ command: "a" }));
    assert.equal(requests[0].body.subject, "user:pinned");
  });
});

test("PRISMOR_SUBJECT env is the fallback when no option or context is set", async () => {
  const requests = [];
  process.env.PRISMOR_SUBJECT = "user:envuser";
  try {
    await withMockFetch(recordingFetch(requests), async () => {
      const run_shell = { execute: async () => "ok" };
      const tools = prismorTools({ run_shell });
      await tools.run_shell.execute({ command: "a" });
      assert.equal(requests[0].body.subject, "user:envuser");
    });
  } finally {
    delete process.env.PRISMOR_SUBJECT;
  }
});

test("no subject → no subject field or header sent", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell });
    await tools.run_shell.execute({ command: "a" });
    assert.equal(requests[0].body.subject, "");
    assert.equal("X-Prismor-Subject" in requests[0].headers, false);
  });
});

test("concurrent requests with different subjects do not bleed", async () => {
  const requests = [];
  await withMockFetch(
    async (_url, init) => {
      requests.push(JSON.parse(init.body));
      await new Promise((r) => setTimeout(r, 5)); // force interleaving
      return { ok: true, json: async () => ALLOW };
    },
    async () => {
      const run_shell = { execute: async ({ command }) => command };
      const tools = prismorTools({ run_shell });
      const users = ["alice", "bob", "carol", "dave"];
      await Promise.all(
        users.map((u) =>
          useSubject(`user:${u}`, async () => {
            for (let i = 0; i < 5; i++) {
              await tools.run_shell.execute({ command: u });
            }
          }),
        ),
      );
      for (const req of requests) {
        assert.equal(req.subject, `user:${req.arguments.command}`);
      }
      assert.equal(requests.length, 20);
    },
  );
});

test("a tool with no execute() is returned unchanged", () => {
  const noop = {};
  const wrapped = prismorTool("noop", noop);
  assert.equal(wrapped, noop);
});

// ── LangChain JS / LangGraph JS ─────────────────────────────────────────────

const { prismorLangChainTool, prismorLangChainTools } = require("../dist/index.js");

function fakeLcTool(name) {
  return {
    name,
    async invoke(input, _config) {
      const args = input && input.type === "tool_call" ? input.args : input;
      return `ran ${name}: ${JSON.stringify(args)}`;
    },
  };
}

test("langchain: guarded invoke() sends tool name and args to the eval-server", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const [tool] = prismorLangChainTools([fakeLcTool("fetch_url")]);
    const out = await tool.invoke({ url: "https://example.com" });
    assert.equal(out, 'ran fetch_url: {"url":"https://example.com"}');
    assert.equal(requests[0].body.tool_name, "fetch_url");
    assert.deepEqual(requests[0].body.arguments, { url: "https://example.com" });
  });
});

test("langchain: ToolCall-shaped input (LangGraph ToolNode) unwraps args for evaluation", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tool = prismorLangChainTool(fakeLcTool("run_shell"));
    const call = { name: "run_shell", args: { command: "echo hi" }, id: "1", type: "tool_call" };
    await tool.invoke(call);
    assert.deepEqual(requests[0].body.arguments, { command: "echo hi" });
  });
});

test("langchain: denied invoke() throws PrismorBlocked and never runs the tool", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ({ allow: false, reason: "nope", findings: [], blocking: null, subject: null }) }),
    async () => {
      let ran = false;
      const tool = prismorLangChainTool({ name: "run_shell", invoke: async () => { ran = true; } });
      await assert.rejects(() => tool.invoke({ command: "rm -rf /" }), PrismorBlocked);
      assert.equal(ran, false);
    },
  );
});

test("langchain: useSubject() attributes guarded invoke() calls", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tool = prismorLangChainTool(fakeLcTool("fetch_url"));
    await useSubject("user:alice", () => tool.invoke({ url: "https://a.com" }));
    await useSubject("user:bob", () => tool.invoke({ url: "https://b.com" }));
    assert.deepEqual(requests.map((r) => r.body.subject), ["user:alice", "user:bob"]);
  });
});

test("langchain: guarding twice is a no-op", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tool = prismorLangChainTool(prismorLangChainTool(fakeLcTool("fetch_url")));
    await tool.invoke({ url: "https://a.com" });
    assert.equal(requests.length, 1);
  });
});
