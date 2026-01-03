import { z } from 'zod';

/**
 * Severity levels for findings
 */
export type Severity = 'error' | 'warning' | 'info' | 'hint';

export const SeveritySchema = z.enum(['error', 'warning', 'info', 'hint']);

/**
 * A single finding from validation
 */
export interface Finding {
  id: string;
  rule: string;
  severity: Severity;
  message: string;
  file?: string;
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  code?: string;
  suggestion?: string;
  metadata?: Record<string, unknown>;
}

export const FindingSchema = z.object({
  id: z.string(),
  rule: z.string(),
  severity: SeveritySchema,
  message: z.string(),
  file: z.string().optional(),
  line: z.number().optional(),
  column: z.number().optional(),
  endLine: z.number().optional(),
  endColumn: z.number().optional(),
  code: z.string().optional(),
  suggestion: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  findings: Finding[];
  summary: {
    total: number;
    errors: number;
    warnings: number;
    info: number;
    hints: number;
  };
  metadata?: Record<string, unknown>;
}

export const ValidationResultSchema = z.object({
  valid: z.boolean(),
  findings: z.array(FindingSchema),
  summary: z.object({
    total: z.number(),
    errors: z.number(),
    warnings: z.number(),
    info: z.number(),
    hints: z.number(),
  }),
  metadata: z.record(z.unknown()).optional(),
});

/**
 * Validation request input
 */
export interface ValidationInput {
  content: string;
  language?: string;
  filename?: string;
  rules?: string[];
  context?: Record<string, unknown>;
}

export const ValidationInputSchema = z.object({
  content: z.string(),
  language: z.string().optional(),
  filename: z.string().optional(),
  rules: z.array(z.string()).optional(),
  context: z.record(z.unknown()).optional(),
});

/**
 * Rule definition
 */
export interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  enabled: boolean;
  options?: Record<string, unknown>;
}

export const RuleDefinitionSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  category: z.string(),
  enabled: z.boolean(),
  options: z.record(z.unknown()).optional(),
});

/**
 * Validator configuration
 */
export interface ValidatorConfig {
  rules?: Record<string, boolean | RuleDefinition>;
  severityOverrides?: Record<string, Severity>;
  ignorePatterns?: string[];
  maxFindings?: number;
}

export const ValidatorConfigSchema = z.object({
  rules: z.record(z.union([z.boolean(), RuleDefinitionSchema])).optional(),
  severityOverrides: z.record(SeveritySchema).optional(),
  ignorePatterns: z.array(z.string()).optional(),
  maxFindings: z.number().optional(),
});
