import { EventEmitter } from "events";
import { Codex } from "@openai/codex-sdk";
import { PHASE_PROMPTS } from "./phases.js";
import type { ExploitCandidate } from "../store/scanStore.js";

export class VulnAgent extends EventEmitter {
  readonly agentId: string;
  readonly candidate: ExploitCandidate;

  constructor(agentId: string, candidate: ExploitCandidate) {
    super();
    this.agentId = agentId;
    this.candidate = candidate;
  }

  async run(): Promise<string> {
    const codex = new Codex();
    const thread = codex.startThread({
      skipGitRepoCheck: true,
      networkAccessEnabled: true,
      sandboxMode: "workspace-write",
    });

    const prompt = PHASE_PROMPTS.exploit(this.candidate);
    const { events } = await thread.runStreamed(prompt);
    let fullText = "";

    for await (const event of events) {
      switch (event.type) {
        case "item.started":
        case "item.updated":
          break;

        case "item.completed":
          if (event.item.type === "agent_message") {
            const text = event.item.text ?? "";
            fullText += text;
            this.emit("agent_message", { agentId: this.agentId, text });
          } else if (event.item.type === "mcp_tool_call") {
            this.emit("tool_call", {
              agentId: this.agentId,
              tool: event.item.tool,
              args: event.item.arguments,
            });
            if (event.item.status === "completed" && event.item.result) {
              const resultText =
                event.item.result.content
                  .map((c) => ("text" in c ? (c as { text: string }).text : ""))
                  .join("");
              this.emit("tool_result", {
                agentId: this.agentId,
                tool: event.item.tool,
                result: resultText.slice(0, 500),
              });
            }
          }
          break;

        case "turn.completed":
          break;

        case "turn.failed":
          throw new Error(
            `Agent ${this.agentId} failed: ${event.error?.message ?? "unknown"}`
          );
      }
    }

    this.emit("agent_done", { agentId: this.agentId, result: fullText });
    return fullText;
  }
}
