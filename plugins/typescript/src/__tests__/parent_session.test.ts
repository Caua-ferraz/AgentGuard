/**
 * parentSessionId: the session that started this one.
 *
 * Mirrors plugins/python/tests/test_parent_session.py. The SDK sends it as
 * `parent_session_id` on /v1/check so the server's sessions API can link a
 * sub-agent's session to the orchestrator's; when unset the request body
 * must not carry the key.
 */

import { AgentGuard } from "../index";

type FetchArgs = [string | URL, RequestInit?];
type FetchMock = jest.Mock<Promise<Response>, FetchArgs>;

function installFetchMock(): FetchMock {
  const m = jest.fn() as unknown as FetchMock;
  (globalThis as { fetch: unknown }).fetch = m;
  m.mockImplementation(async () =>
    new Response(JSON.stringify({ decision: "ALLOW", reason: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  );
  return m;
}

function sentBody(m: FetchMock): Record<string, unknown> {
  const init = m.mock.calls[m.mock.calls.length - 1][1];
  return JSON.parse(String(init?.body));
}

describe("AgentGuard parentSessionId", () => {
  const cases: Array<[string, string | undefined, string | undefined, string | undefined]> = [
    ["neither set", undefined, undefined, undefined],
    ["client option", "orch-1", undefined, "orch-1"],
    ["per-call option", undefined, "orch-2", "orch-2"],
    ["per-call option wins", "orch-1", "orch-2", "orch-2"],
  ];
  test.each(cases)("%s", async (_name, clientParent, callParent, want) => {
    const fetchMock = installFetchMock();
    const guard = new AgentGuard({
      baseUrl: "http://example.test",
      agentId: "sub",
      ...(clientParent !== undefined ? { parentSessionId: clientParent } : {}),
    });
    await guard.check("shell", {
      command: "ls",
      sessionId: "sub-1",
      ...(callParent !== undefined ? { parentSessionId: callParent } : {}),
    });
    const body = sentBody(fetchMock);
    expect(body.session_id).toBe("sub-1");
    if (want === undefined) {
      expect(body).not.toHaveProperty("parent_session_id");
    } else {
      expect(body.parent_session_id).toBe(want);
    }
  });

  test("parentSessionId is a known constructor option", () => {
    expect(() => new AgentGuard({ parentSessionId: "orch" })).not.toThrow();
  });
});
