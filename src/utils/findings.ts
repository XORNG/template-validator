import type { Finding, Severity, ValidationResult } from '../types/index.js';

/**
 * Format findings for display
 */
export function formatFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return 'No issues found';
  }

  const lines: string[] = [];
  const grouped = groupByFile(findings);

  for (const [file, fileFindings] of grouped) {
    lines.push(`\n${file || 'Unknown file'}:`);
    
    for (const finding of fileFindings) {
      const location = finding.line
        ? `${finding.line}:${finding.column || 1}`
        : '';
      const severity = finding.severity.toUpperCase().padEnd(7);
      
      lines.push(`  ${location.padEnd(8)} ${severity} ${finding.message} [${finding.rule}]`);
      
      if (finding.suggestion) {
        lines.push(`           Suggestion: ${finding.suggestion}`);
      }
    }
  }

  return lines.join('\n');
}

/**
 * Merge multiple finding arrays
 */
export function mergeFindings(...findingArrays: Finding[][]): Finding[] {
  const merged: Finding[] = [];
  const seen = new Set<string>();

  for (const findings of findingArrays) {
    for (const finding of findings) {
      // Create a key for deduplication
      const key = `${finding.rule}:${finding.file}:${finding.line}:${finding.column}`;
      if (!seen.has(key)) {
        seen.add(key);
        merged.push(finding);
      }
    }
  }

  return merged;
}

/**
 * Filter findings by severity
 */
export function filterBySeverity(
  findings: Finding[],
  minSeverity: Severity
): Finding[] {
  const severityOrder: Record<Severity, number> = {
    // Security severity levels
    critical: 0,
    high: 1,
    // Lint severity levels (error maps to high)
    error: 1,
    medium: 2,
    warning: 2,
    low: 3,
    info: 3,
    hint: 4,
  };

  const minLevel = severityOrder[minSeverity];
  return findings.filter(f => severityOrder[f.severity] <= minLevel);
}

/**
 * Group findings by file
 */
export function groupByFile(findings: Finding[]): Map<string, Finding[]> {
  const grouped = new Map<string, Finding[]>();

  for (const finding of findings) {
    const file = finding.file || '';
    const existing = grouped.get(file) || [];
    existing.push(finding);
    grouped.set(file, existing);
  }

  // Sort findings within each file by line number
  for (const [file, fileFindings] of grouped) {
    fileFindings.sort((a, b) => (a.line || 0) - (b.line || 0));
  }

  return grouped;
}

/**
 * Group findings by rule
 */
export function groupByRule(findings: Finding[]): Map<string, Finding[]> {
  const grouped = new Map<string, Finding[]>();

  for (const finding of findings) {
    const existing = grouped.get(finding.rule) || [];
    existing.push(finding);
    grouped.set(finding.rule, existing);
  }

  return grouped;
}

/**
 * Create summary from findings
 */
export function createSummary(findings: Finding[]): ValidationResult['summary'] {
  return {
    total: findings.length,
    errors: findings.filter(f => f.severity === 'error').length,
    warnings: findings.filter(f => f.severity === 'warning').length,
    info: findings.filter(f => f.severity === 'info').length,
    hints: findings.filter(f => f.severity === 'hint').length,
  };
}

/**
 * Sort findings by severity
 */
export function sortBySeverity(findings: Finding[]): Finding[] {
  const severityOrder: Record<Severity, number> = {
    // Security severity levels
    critical: 0,
    high: 1,
    // Lint severity levels (error maps to high)
    error: 1,
    medium: 2,
    warning: 2,
    low: 3,
    info: 3,
    hint: 4,
  };

  return [...findings].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );
}

/**
 * Convert findings to SARIF format
 */
export function toSarif(
  findings: Finding[],
  toolName: string,
  toolVersion: string
): object {
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version: toolVersion,
            rules: Array.from(new Set(findings.map(f => f.rule))).map(rule => ({
              id: rule,
              shortDescription: { text: rule },
            })),
          },
        },
        results: findings.map(f => ({
          ruleId: f.rule,
          level: f.severity === 'error' ? 'error' : f.severity === 'warning' ? 'warning' : 'note',
          message: { text: f.message },
          locations: f.file
            ? [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.file },
                    region: f.line
                      ? {
                          startLine: f.line,
                          startColumn: f.column,
                          endLine: f.endLine,
                          endColumn: f.endColumn,
                        }
                      : undefined,
                  },
                },
              ]
            : undefined,
        })),
      },
    ],
  };
}
