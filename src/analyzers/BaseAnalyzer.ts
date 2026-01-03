import type { Logger } from '@xorng/template-base';
import type { Finding, Severity, ValidationInput } from '../types/index.js';

/**
 * Result from an analyzer
 */
export interface AnalyzerResult {
  findings: Finding[];
  metadata?: Record<string, unknown>;
}

export { Finding };

/**
 * Context passed to analyzers
 */
export interface AnalyzerContext {
  logger: Logger;
  requestId: string;
  config?: Record<string, unknown>;
}

/**
 * Base class for analyzers
 * 
 * Analyzers implement specific validation logic (e.g., style checking,
 * security scanning, complexity analysis).
 */
export abstract class BaseAnalyzer {
  public readonly name: string;
  public readonly description: string;
  public readonly category: string;
  protected defaultSeverity: Severity;

  constructor(
    name: string,
    description: string,
    category: string,
    defaultSeverity: Severity = 'warning'
  ) {
    this.name = name;
    this.description = description;
    this.category = category;
    this.defaultSeverity = defaultSeverity;
  }

  /**
   * Analyze the input and return findings
   */
  abstract analyze(
    input: ValidationInput,
    context: AnalyzerContext
  ): Promise<AnalyzerResult>;

  /**
   * Check if this analyzer supports the given input
   */
  supports(input: ValidationInput): boolean {
    return true;
  }

  /**
   * Create a finding
   */
  protected createFinding(
    rule: string,
    message: string,
    options: Partial<Omit<Finding, 'id' | 'rule' | 'message'>> = {}
  ): Finding {
    return {
      id: `${this.name}-${crypto.randomUUID().slice(0, 8)}`,
      rule: `${this.name}/${rule}`,
      severity: options.severity || this.defaultSeverity,
      message,
      ...options,
    };
  }

  /**
   * Parse code into lines for analysis
   */
  protected parseLines(content: string): string[] {
    return content.split('\n');
  }

  /**
   * Find pattern matches in content
   */
  protected findMatches(
    content: string,
    pattern: RegExp,
    rule: string,
    messageTemplate: (match: RegExpExecArray) => string,
    severityOverride?: Severity
  ): Finding[] {
    const findings: Finding[] = [];
    const lines = this.parseLines(content);
    
    let match: RegExpExecArray | null;
    const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    
    while ((match = globalPattern.exec(content)) !== null) {
      const position = this.getPosition(content, match.index);
      
      findings.push(this.createFinding(rule, messageTemplate(match), {
        severity: severityOverride,
        line: position.line,
        column: position.column,
        code: lines[position.line - 1],
      }));
    }

    return findings;
  }

  /**
   * Get line and column from character index
   */
  protected getPosition(
    content: string,
    index: number
  ): { line: number; column: number } {
    const before = content.slice(0, index);
    const lines = before.split('\n');
    return {
      line: lines.length,
      column: lines[lines.length - 1].length + 1,
    };
  }
}
