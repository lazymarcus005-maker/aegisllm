# 12: Tool call/result inspection + RESTRICT_TOOLS

**What to build:** The third and fourth data boundaries: model-emitted tool calls are inspected before execution and tool results before they re-enter model context, both through the same core pipeline; RESTRICT_TOOLS actually removes or rejects tools. From the user's perspective: a tool call running `env | grep KEY` is blocked or the tool is stripped (UC-006), and a tool result containing `Authorization: Bearer …` never re-enters model context raw (UC-007).

**Blocked by:** 07 (outbound protection + transform machinery), 09 (semantic tool-intent questions).

**Status:** done

- [x] Internal inspect_tool_call / inspect_tool_result APIs reuse the core pipeline with directions TOOL_CALL / TOOL_RESULT (FR-016/017, T-024)
- [x] Tool-call scanning: secret/exfiltration findings → policy block or restrict (UC-006)
- [x] Tool-result scanning: secret finding → redact or block; raw credential never re-enters model context (UC-007)
- [x] RESTRICT_TOOLS removes dangerous tools from the request or rejects the specific tool call and can route to review — never a prompt-level "please don't" (T-025)
- [x] Full MCP proxy remains deferred; interfaces shaped so V2 doesn't redesign (architecture §14)
