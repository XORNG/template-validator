// Replace:
// import { Logger } from '@xorng/template-base';
// With one of these depending on your project setup:
import { Logger } from '../types/Logger'; // If local
// OR
import type { Logger } from 'winston'; // If using winston
// OR verify package exists in package.json
  type SubAgentConfig,
  type ProcessRequest,
  createToolHandler,
} from '@xorng/template-base';
import { z } from 'zod';
import { BaseAnalyzer, type AnalyzerResult } from '../analyzers/BaseAnalyzer.js';
import type {
  ValidationInput,
  ValidationResult,
  ValidatorConfig,
  Finding,
  Severity,
} from '../types/index.js';
import { mergeFindings, createSummary } from '../utils/findings.js';

/**
 * Base class for validator sub-agents
 * 
 * Provides common validation infrastructure:
 * - Analyzer registration and execution
 * - Finding aggregation
 * - Standard validation tools
 */
export abstract class BaseValidator extends BaseSubAgent {
  protected analyzers: Map<string, BaseAnalyzer> = new Map();
  protected validatorConfig: ValidatorConfig;

  constructor(
    metadata: SubAgentMetadata,
    config?: SubAgentConfig,
    validatorConfig?: ValidatorConfig
  ) {
    // Ensure 'validate' capability
    const capabilities = metadata.capabilities.includes('validate')
      ? metadata.capabilities
      : [...metadata.capabilities, 'validate' as const];

    super({ ...metadata, capabilities }, config);
    this.validatorConfig = validatorConfig || {};

    // Register standard tools
    this.registerStandardTools();
  }

  /**
   * Register an analyzer
   */
  protected registerAnalyzer(analyzer: BaseAnalyzer): void {
    if (this.analyzers.has(analyzer.name)) {
      this.logger.warn({ analyzer: analyzer.name }, 'Overwriting existing analyzer');
    }
    this.analyzers.set(analyzer.name, analyzer);
    this.logger.debug({ analyzer: analyzer.name }, 'Analyzer registered');
  }

  /**
   * Get all registered analyzers
   */
  getAnalyzers(): Map<string, BaseAnalyzer> {
    return this.analyzers;
  }

  /**
   * Run validation with all applicable analyzers
   */
  async validate(input: ValidationInput): Promise<ValidationResult> {
    const requestId = crypto.randomUUID();
    const startTime = Date.now();
    const allFindings: Finding[] = [];

    this.logger.info({
      requestId,
      language: input.language,
      filename: input.filename,
      analyzerCount: this.analyzers.size,
    }, 'Starting validation');

    // Run each analyzer
    for (const [name, analyzer] of this.analyzers) {
      // Skip if analyzer doesn't support this input
      if (!analyzer.supports(input)) {
        this.logger.debug({ analyzer: name }, 'Analyzer skipped - not supported');
        continue;
      }

      // Skip if rules filter excludes this analyzer
      if (input.rules && !input.rules.some(r => r.startsWith(name))) {
        this.logger.debug({ analyzer: name }, 'Analyzer skipped - not in rules filter');
        continue;
      }

      try {
        const result = await analyzer.analyze(input, {
          logger: this.logger.child({ analyzer: name }),
          requestId,
          config: (this.validatorConfig.rules?.[name] ?? {}) as Record<string, unknown>,
        });

        allFindings.push(...result.findings);
        this.logger.debug({
          analyzer: name,
          findingCount: result.findings.length,
        }, 'Analyzer completed');
      } catch (error) {
        this.logger.error({ analyzer: name, error }, 'Analyzer failed');
      }
    }

    // Apply severity overrides
    const adjustedFindings = this.applySeverityOverrides(allFindings);

    // Filter by ignore patterns
    const filteredFindings = this.applyIgnorePatterns(adjustedFindings, input.filename);

    // Limit findings if configured
    const limitedFindings = this.validatorConfig.maxFindings
      ? filteredFindings.slice(0, this.validatorConfig.maxFindings)
      : filteredFindings;

    const summary = createSummary(limitedFindings);

    this.logger.info({
      requestId,
      durationMs: Date.now() - startTime,
      summary,
    }, 'Validation completed');

    return {
      valid: summary.errors === 0,
      findings: limitedFindings,
      summary,
      metadata: {
        durationMs: Date.now() - startTime,
        analyzersRun: this.analyzers.size,
      },
    };
  }

  /**
   * Register standard validation tools
   */
  private registerStandardTools(): void {
    // Main validate tool
    this.registerTool(createToolHandler({
      name: 'validate',
      description: 'Validate content against configured rules',
      inputSchema: z.object({
        content: z.string().describe('Content to validate'),
        language: z.string().optional().describe('Programming language'),
        filename: z.string().optional().describe('Source filename'),
        rules: z.array(z.string()).optional().describe('Specific rules to run'),
      }),
      handler: async (input) => {
        return this.validate(input);
      },
    }));

    // List rules tool
    this.registerTool(createToolHandler({
      name: 'list-rules',
      description: 'List all available validation rules',
      inputSchema: z.object({}),
      handler: async () => {
        const rules: Array<{
          analyzer: string;
          category: string;
          description: string;
        }> = [];

        for (const [name, analyzer] of this.analyzers) {
          rules.push({
            analyzer: name,
            category: analyzer.category,
            description: analyzer.description,
          });
        }

        return { rules };
      },
    }));
  }

  /**
   * Apply severity overrides from config
   */
  private applySeverityOverrides(findings: Finding[]): Finding[] {
    if (!this.validatorConfig.severityOverrides) {
      return findings;
    }

    return findings.map(finding => {
      const override = this.validatorConfig.severityOverrides?.[finding.rule];
      if (override) {
        return { ...finding, severity: override };
      }
      return finding;
    });
  }

  /**
   * Filter findings based on ignore patterns
   */
  private applyIgnorePatterns(findings: Finding[], filename?: string): Finding[] {
    if (!this.validatorConfig.ignorePatterns || !filename) {
      return findings;
    }

    return findings.filter(finding => {
      const targetFile = finding.file || filename;
      return !this.validatorConfig.ignorePatterns!.some(pattern => {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(targetFile);
      });
    });
  }

  /**
   * Handle process requests
   */
  protected async handleRequest(
    request: ProcessRequest,
    requestId: string
  ): Promise<unknown> {
    if (request.type === 'validate') {
      return this.validate({
        content: request.content,
        ...request.options as Partial<ValidationInput>,
      });
    }

    // Delegate to tool execution
    return this.executeTool(request.type, request, requestId);
  }
}
