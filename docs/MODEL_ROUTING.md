# Model routing

## Until August 7, 2026

### Claude — primary planner and researcher
Use for long-context architecture review, capture design, evidence-ledger maintenance, Ghidra/IDA investigation plans, and bounded prompts. Claude must label facts versus hypotheses and must not implement beyond the current phase gate.

### Qwen — independent read-only auditor
Use after each evidence rung. It reviews claims, missing counter-evidence, fixture derivation, and whether the next phase is authorized. It does not edit the repository during an audit.

### DeepSeek — routine implementation support
Use for capture-normalization scripts, schema extraction, tests, documentation cleanup, and low-risk Python work after Claude has fixed the contract.

### MiMo — repetitive analysis assistant
Use for endpoint grouping, table normalization, log classification, and generating candidate schemas. Its output requires verification against evidence.

## From August 7, 2026

### Codex — exact implementation and repository work
Preferred for test-first Python services, C/C++ shim work, build-system changes, packet parsers, deterministic fixtures, commits, and CI. Manually select it for risky client/binary-facing changes.

### Kimi — long-context synthesis and exploratory RE
Preferred for large capture corpora, cross-file binary observations, protocol/state-machine synthesis, and comparing many sessions. Use Codex to turn accepted findings into exact patches.

## Default pairing

- Planner: Claude or Kimi
- Builder: Codex
- Independent auditor: Qwen
- Bulk extraction: DeepSeek or MiMo

Never let the builder generate the expected values used to judge its own implementation when retail evidence exists.
