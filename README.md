# XORNG Template Validator

Template for building validation-focused sub-agents in the XORNG framework.

## Overview

`@xorng/template-validator` provides the infrastructure for building validators:

- **BaseValidator** - Base class for validator sub-agents
- **BaseAnalyzer** - Base class for analysis implementations
- **Finding utilities** - Tools for working with validation findings

## Installation

```bash
npm install @xorng/template-validator
```

## Quick Start

```typescript
import {
  BaseValidator,
  BaseAnalyzer,
  startValidator,
  type ValidationInput,
  type AnalyzerResult,
} from '@xorng/template-validator';

// Create a custom analyzer
class MyAnalyzer extends BaseAnalyzer {
  constructor() {
    super('my-analyzer', 'Checks for issues', 'custom', 'warning');
  }

  async analyze(input: ValidationInput): Promise<AnalyzerResult> {
    const findings = [];
    
    // Check for TODO comments
    const todoPattern = /TODO:/gi;
    findings.push(...this.findMatches(
      input.content,
      todoPattern,
      'no-todo',
      () => 'TODO comment found'
    ));

    return { findings };
  }
}

// Create the validator
class MyValidator extends BaseValidator {
  constructor() {
    super({
      name: 'my-validator',
      version: '1.0.0',
      description: 'Custom code validator',
      capabilities: ['validate', 'analyze'],
    });

    this.registerAnalyzer(new MyAnalyzer());
  }
}

// Start the MCP server
startValidator(new MyValidator());
```

## Building Analyzers

### BaseAnalyzer

```typescript
abstract class BaseAnalyzer {
  constructor(
    name: string,
    description: string,
    category: string,
    defaultSeverity: Severity = 'warning'
  );

  // Must implement
  abstract analyze(input: ValidationInput, context: AnalyzerContext): Promise<AnalyzerResult>;

  // Optional - check if analyzer supports input
  supports(input: ValidationInput): boolean;

  // Helper methods
  protected createFinding(rule: string, message: string, options?: Partial<Finding>): Finding;
  protected parseLines(content: string): string[];
  protected findMatches(content: string, pattern: RegExp, rule: string, messageTemplate: Function): Finding[];
  protected getPosition(content: string, index: number): { line: number; column: number };
}
```

### Example Analyzers

**Pattern-based analyzer:**

```typescript
class SecurityAnalyzer extends BaseAnalyzer {
  constructor() {
    super('security', 'Security vulnerability scanner', 'security', 'error');
  }

  async analyze(input: ValidationInput): Promise<AnalyzerResult> {
    const findings = [];

    // Check for hardcoded secrets
    const secretPatterns = [
      { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi, rule: 'no-hardcoded-api-key' },
      { pattern: /password\s*[:=]\s*['"][^'"]+['"]/gi, rule: 'no-hardcoded-password' },
    ];

    for (const { pattern, rule } of secretPatterns) {
      findings.push(...this.findMatches(
        input.content,
        pattern,
        rule,
        (match) => `Potential hardcoded secret: ${match[0].slice(0, 20)}...`
      ));
    }

    return { findings };
  }
}
```

**AST-based analyzer (conceptual):**

```typescript
class ComplexityAnalyzer extends BaseAnalyzer {
  constructor() {
    super('complexity', 'Code complexity analyzer', 'metrics', 'warning');
  }

  async analyze(input: ValidationInput): Promise<AnalyzerResult> {
    const findings = [];
    
    // Parse AST (using your preferred parser)
    const ast = parseCode(input.content, input.language);
    
    // Analyze functions
    for (const func of findFunctions(ast)) {
      const complexity = calculateCyclomaticComplexity(func);
      
      if (complexity > 10) {
        findings.push(this.createFinding(
          'high-complexity',
          `Function has cyclomatic complexity of ${complexity} (max: 10)`,
          {
            severity: complexity > 20 ? 'error' : 'warning',
            line: func.loc.start.line,
            metadata: { complexity },
          }
        ));
      }
    }

    return { findings };
  }
}
```

## Building Validators

### BaseValidator

```typescript
abstract class BaseValidator extends BaseSubAgent {
  constructor(
    metadata: SubAgentMetadata,
    config?: SubAgentConfig,
    validatorConfig?: ValidatorConfig
  );

  // Register analyzers
  protected registerAnalyzer(analyzer: BaseAnalyzer): void;

  // Run validation
  async validate(input: ValidationInput): Promise<ValidationResult>;

  // Built-in tools: 'validate', 'list-rules'
}
```

### Configuration

```typescript
const validator = new MyValidator({
  rules: {
    'security': true,
    'style': { enabled: true, options: { indentSize: 2 } },
  },
  severityOverrides: {
    'security/no-eval': 'error',
  },
  ignorePatterns: ['*.test.ts', 'node_modules/**'],
  maxFindings: 100,
});
```

## Types

### Finding

```typescript
interface Finding {
  id: string;           // Unique identifier
  rule: string;         // Rule ID (e.g., 'security/no-eval')
  severity: Severity;   // 'error' | 'warning' | 'info' | 'hint'
  message: string;      // Human-readable message
  file?: string;        // Source file
  line?: number;        // Line number
  column?: number;      // Column number
  code?: string;        // Source code snippet
  suggestion?: string;  // Fix suggestion
}
```

### ValidationResult

```typescript
interface ValidationResult {
  valid: boolean;       // true if no errors
  findings: Finding[];  // All findings
  summary: {
    total: number;
    errors: number;
    warnings: number;
    info: number;
    hints: number;
  };
}
```

## Utilities

```typescript
import {
  formatFindings,
  mergeFindings,
  filterBySeverity,
  groupByFile,
  groupByRule,
  sortBySeverity,
  toSarif,
} from '@xorng/template-validator';

// Format for display
console.log(formatFindings(findings));

// Merge from multiple sources
const all = mergeFindings(findingsA, findingsB);

// Filter to errors and warnings only
const important = filterBySeverity(findings, 'warning');

// Group by file for reporting
const byFile = groupByFile(findings);

// Export as SARIF
const sarif = toSarif(findings, 'my-validator', '1.0.0');
```

## License

MIT
