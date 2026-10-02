import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ClientPool } from "./client.js";
import type { Config } from "./config.js";
import { registerTools, SERVER_INSTRUCTIONS } from "./tools.js";

export const VERSION = "0.1.0";

export function createServer(config: Config): { server: McpServer; pool: ClientPool } {
  const pool = new ClientPool(config);
  const server = new McpServer({ name: "splunk-mcp", version: VERSION }, { instructions: SERVER_INSTRUCTIONS });
  registerTools(server, config, pool);
  return { server, pool };
}
