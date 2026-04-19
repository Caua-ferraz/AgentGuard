/**
 * Jest configuration for the AgentGuard TypeScript SDK.
 *
 * ts-jest compiles the TS sources on demand so we don't maintain a
 * separate tsc pipeline for tests. Tests live under src/__tests__/ and
 * are intentionally excluded from the production build via tsconfig.json.
 */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/src"],
  testMatch: ["**/__tests__/**/*.test.ts", "**/?(*.)+(spec|test).ts"],
  // Keep the production build free of test files; ts-jest still compiles
  // them on the fly for the test run.
  transform: {
    "^.+\\.ts$": ["ts-jest", { tsconfig: { rootDir: "./src" } }],
  },
  // waitForApproval polls via setTimeout; under a short deadline a pending
  // timer can briefly outlive the test. forceExit avoids a CI hang without
  // masking real async leaks — the detectOpenHandles path is still
  // available on demand via `npx jest --detectOpenHandles`.
  forceExit: true,
};
