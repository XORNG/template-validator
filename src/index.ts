/**
 * XORNG Template Validator
 * 
 * Template for building validation-focused sub-agents.
 */

// Base validator class
export { BaseValidator } from './base/BaseValidator.js';

// Analyzer abstractions
export { BaseAnalyzer, type AnalyzerResult, type Finding } from './analyzers/BaseAnalyzer.js';

// Types
export * from './types/index.js';

// Utilities
export { createValidatorServer, startValidator } from './server.js';
export { 
  formatFindings, 
  mergeFindings,
  filterBySeverity,
  groupByFile,
} from './utils/findings.js';
