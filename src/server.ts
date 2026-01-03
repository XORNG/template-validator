import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createLogger, registerTools, type Logger } from '@xorng/template-base';
import { BaseValidator } from './base/BaseValidator.js';

/**
 * Options for creating a validator server
 */
export interface ValidatorServerOptions {
  validator: BaseValidator;
  logLevel?: string;
}

/**
 * Create and start an MCP server for a validator
 */
export function createValidatorServer(options: ValidatorServerOptions): {
  server: McpServer;
  transport: StdioServerTransport;
  logger: Logger;
  start: () => Promise<void>;
} {
  const { validator, logLevel = 'info' } = options;
  const metadata = validator.getMetadata();
  
  const logger = createLogger(logLevel, metadata.name);

  const server = new McpServer({
    name: metadata.name,
    version: metadata.version,
  });

  const transport = new StdioServerTransport();

  // Register all validator tools
  registerTools(server, validator.getTools(), logger);

  const start = async () => {
    await validator.initialize();
    
    logger.info({
      name: metadata.name,
      version: metadata.version,
      analyzers: Array.from(validator.getAnalyzers().keys()),
    }, 'Starting validator MCP server');

    await server.connect(transport);
    
    logger.info('Validator MCP server connected');

    // Handle shutdown
    process.on('SIGINT', async () => {
      logger.info('Shutting down...');
      await validator.shutdown();
      process.exit(0);
    });
  };

  return { server, transport, logger, start };
}

/**
 * Quick start helper for validators
 */
export async function startValidator(validator: BaseValidator): Promise<void> {
  const { start } = createValidatorServer({ validator });
  await start();
}
