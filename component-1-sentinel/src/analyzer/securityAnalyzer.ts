/**
 * Sentinel — Security Analyzer
 *
 * Orchestrates all security rules. This is the main analysis engine called
 * by the VS Code extension whenever the document changes.
 */

import { SqlInjectionRule } from '../rules/sqlInjectionRule.js';
import { XssRule } from '../rules/xssRule.js';
import { HardcodedSecretRule } from '../rules/hardcodedSecretRule.js';
import { BrokenAccessControlRule } from '../rules/brokenAccessControlRule.js';
import { CryptographicFailuresRule } from '../rules/cryptographicFailuresRule.js';
import { InjectionRule } from '../rules/injectionRule.js';
import { InsecureDesignRule } from '../rules/insecureDesignRule.js';
import { SecurityMisconfigurationRule } from '../rules/securityMisconfigurationRule.js';
import { VulnerableComponentsRule } from '../rules/vulnerableComponentsRule.js';
import { AuthFailuresRule } from '../rules/authFailuresRule.js';
import { IntegrityFailuresRule } from '../rules/integrityFailuresRule.js';
import { LoggingFailuresRule } from '../rules/loggingFailuresRule.js';
import { SsrfRule } from '../rules/ssrfRule.js';
import { SecurityFinding, SecurityRule } from './types.js';

export class SecurityAnalyzer {
  private rules: SecurityRule[];

  constructor() {
    // OWASP Top 10 (2021) — one detector family per category, plus the original
    // specialised SQL / XSS / secret rules that A03 / A07 build on.
    this.rules = [
      new BrokenAccessControlRule(),      // A01
      new CryptographicFailuresRule(),    // A02
      new SqlInjectionRule(),             // A03 (SQL)
      new XssRule(),                      // A03 (XSS)
      new InjectionRule(),                // A03 (command / NoSQL / LDAP / XPath / SSTI)
      new InsecureDesignRule(),           // A04
      new SecurityMisconfigurationRule(), // A05
      new VulnerableComponentsRule(),     // A06
      new HardcodedSecretRule(),          // A07 (CWE-798)
      new AuthFailuresRule(),             // A07 (authn design)
      new IntegrityFailuresRule(),        // A08
      new LoggingFailuresRule(),          // A09
      new SsrfRule(),                     // A10
    ];
  }

  /**
   * Analyze a document and return all security findings.
   *
   * @param text - Full document text content
   * @param fileName - Absolute path to the file
   * @param languageId - VS Code language identifier (e.g. 'csharp', 'javascript')
   * @returns Array of SecurityFinding objects (may be empty if no issues found)
   */
  analyze(text: string, fileName: string, languageId: string): SecurityFinding[] {
    const allFindings: SecurityFinding[] = [];

    for (const rule of this.rules) {
      try {
        const findings = rule.analyze(text, fileName, languageId);
        allFindings.push(...findings);
      } catch (err) {
        // Never let a single rule crash the whole analysis
        console.error(`[Sentinel] Rule ${rule.ruleId} threw an error:`, err);
      }
    }

    // Sort by severity (CRITICAL first) then by line number
    return allFindings.sort((a, b) => {
      const severityOrder: Record<string, number> = {
        CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
      };
      const sA = severityOrder[a.severity] ?? 99;
      const sB = severityOrder[b.severity] ?? 99;
      if (sA !== sB) {
        return sA - sB;
      }
      return a.lineNumber - b.lineNumber;
    });
  }

  /**
   * Return the list of registered rules.
   */
  getRules(): SecurityRule[] {
    return [...this.rules];
  }

  /**
   * Return summary stats for a set of findings.
   */
  summarize(findings: SecurityFinding[]): AnalysisSummary {
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};

    for (const f of findings) {
      byType[f.type] = (byType[f.type] || 0) + 1;
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }

    return {
      totalFindings: findings.length,
      criticalCount: bySeverity['CRITICAL'] || 0,
      highCount: bySeverity['HIGH'] || 0,
      mediumCount: bySeverity['MEDIUM'] || 0,
      lowCount: bySeverity['LOW'] || 0,
      byType,
    };
  }
}

export interface AnalysisSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  byType: Record<string, number>;
}
