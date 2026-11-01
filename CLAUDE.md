# Claude Code implementation brief

Follow AGENTS.md. You are the primary implementer. ChatGPT owns research/specification/review in this shared repository.

Implement docs/MILESTONE-1.md now, starting with M1a local rehearsal. Read docs/ARCHITECTURE.md and docs/RESEARCH.md. Use npm workspaces, strict TypeScript, the upstream x402 SDK and official MCP SDK. Pin dependency versions in a lockfile. Research installed/current upstream APIs before coding.

You may install development dependencies from official registries and use an ephemeral local EVM. No public-chain writes, mainnet operations, publishing, or real money. Do not expose any keys to your own context or to ChatGPT. Generate test keys within processes; suppress chain startup key dumps. Do not inspect credentials.

Own package/application source, tests, package manifests, lockfile, CI, README implementation instructions, and docs/IMPLEMENTATION-STATUS.md. Do not modify architectural/research documents without discussing a conflict in the status file. Do not commit until repository identity is valid; ChatGPT will handle initial Git setup and review.

First deliver a working, tested vertical slice, not every future module. If a standard/dependency blocks the planned path, record the concrete error and implement independent portions. Update docs/IMPLEMENTATION-STATUS.md with commands run, pass/fail counts, files changed, evidence locations, running process IDs if any, and remaining blockers. Stop at public spending approval boundaries, continue safe local work.
