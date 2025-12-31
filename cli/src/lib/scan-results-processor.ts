/**
 * Scan Results Processor for SecureScan CLI
 * 
 * Handles processing, formatting, and converting scan results between different formats.
 * Supports SARIF, JSON, HTML, CSV, and custom report formats.
 */

export interface VulnerabilityResult {
  id?: string;
  scanner: string;
  ruleId: string;
  ruleName: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
  location: {
    file: string;
    line?: number;
    column?: number;
    endLine?: number;
    endColumn?: number;
  };
  cwe?: string[];
  cve?: string[];
  fix?: {
    suggestion: string;
    effort: 'low' | 'medium' | 'high';
  };
  metadata?: Record<string, any>;
}

export interface ScanSummary {
  totalVulnerabilities: number;
  vulnerabilitiesBySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  vulnerabilitiesByScanner: Record<string, number>;
  vulnerabilitiesByCategory: Record<string, number>;
  scanDuration?: number;
  timestamp: string;
}

export interface ProcessedResults {
  summary: ScanSummary;
  vulnerabilities: VulnerabilityResult[];
  metadata: {
    version: string;
    scanId?: string;
    projectId?: string;
    generatedAt: string;
  };
}

export class ScanResultsProcessor {
  /**
   * Process raw scan results from multiple scanners
   */
  async process(rawResults: any[]): Promise<ProcessedResults> {
    const vulnerabilities: VulnerabilityResult[] = [];
    
    for (const result of rawResults) {
      const processed = await this.processScannerResult(result);
      vulnerabilities.push(...processed);
    }

    const summary = this.generateSummary(vulnerabilities);
    
    return {
      summary,
      vulnerabilities,
      metadata: {
        version: '1.0.0',
        generatedAt: new Date().toISOString()
      }
    };
  }

  /**
   * Process results from a specific scanner
   */
  private async processScannerResult(result: any): Promise<VulnerabilityResult[]> {
    const scannerType = result.scannerType || this.detectScannerType(result);
    
    switch (scannerType) {
      case 'sast':
        return this.processSemgrepResults(result);
      case 'sca':
        return this.processTrivyResults(result);
      case 'dast':
        return this.processZapResults(result);
      case 'secrets':
        return this.processGitleaksResults(result);
      case 'iac':
        return this.processCheckovResults(result);
      case 'container':
        return this.processTrivyContainerResults(result);
      default:
        return this.processGenericResults(result, scannerType);
    }
  }

  /**
   * Detect scanner type from result structure
   */
  private detectScannerType(result: any): string {
    if (result.results && Array.isArray(result.results)) {
      // Semgrep format
      if (result.results[0]?.check_id) return 'sast';
      // Trivy format
      if (result.Results) return 'sca';
    }
    
    if (result.site && result.site[0]?.alerts) {
      // ZAP format
      return 'dast';
    }
    
    if (result.DetectorName || result.RuleID) {
      // Gitleaks format
      return 'secrets';
    }
    
    if (result.check_type) {
      // Checkov format
      return 'iac';
    }
    
    return 'unknown';
  }

  /**
   * Process Semgrep (SAST) results
   */
  private processSemgrepResults(result: any): VulnerabilityResult[] {
    if (!result.results) return [];
    
    return result.results.map((finding: any) => ({
      scanner: 'semgrep',
      ruleId: finding.check_id,
      ruleName: finding.check_id,
      severity: this.mapSemgrepSeverity(finding.extra?.severity),
      category: finding.extra?.metadata?.category || 'security',
      description: finding.extra?.message || finding.check_id,
      location: {
        file: finding.path,
        line: finding.start?.line,
        column: finding.start?.col,
        endLine: finding.end?.line,
        endColumn: finding.end?.col
      },
      cwe: finding.extra?.metadata?.cwe ? [finding.extra.metadata.cwe] : undefined,
      fix: finding.extra?.fix ? {
        suggestion: finding.extra.fix,
        effort: 'medium'
      } : undefined,
      metadata: {
        confidence: finding.extra?.metadata?.confidence,
        impact: finding.extra?.metadata?.impact,
        likelihood: finding.extra?.metadata?.likelihood
      }
    }));
  }

  /**
   * Process Trivy (SCA) results
   */
  private processTrivyResults(result: any): VulnerabilityResult[] {
    if (!result.Results) return [];
    
    const vulnerabilities: VulnerabilityResult[] = [];
    
    for (const scanResult of result.Results) {
      if (!scanResult.Vulnerabilities) continue;
      
      for (const vuln of scanResult.Vulnerabilities) {
        vulnerabilities.push({
          scanner: 'trivy',
          ruleId: vuln.VulnerabilityID,
          ruleName: vuln.Title || vuln.VulnerabilityID,
          severity: this.mapTrivySeverity(vuln.Severity),
          category: 'dependency',
          description: vuln.Description || vuln.Title,
          location: {
            file: scanResult.Target,
            line: 1
          },
          cve: [vuln.VulnerabilityID],
          fix: vuln.FixedVersion ? {
            suggestion: `Update to version ${vuln.FixedVersion}`,
            effort: 'low'
          } : undefined,
          metadata: {
            packageName: vuln.PkgName,
            installedVersion: vuln.InstalledVersion,
            fixedVersion: vuln.FixedVersion,
            references: vuln.References
          }
        });
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Process OWASP ZAP (DAST) results
   */
  private processZapResults(result: any): VulnerabilityResult[] {
    if (!result.site?.[0]?.alerts) return [];
    
    const vulnerabilities: VulnerabilityResult[] = [];
    
    for (const alert of result.site[0].alerts) {
      for (const instance of alert.instances || [{}]) {
        vulnerabilities.push({
          scanner: 'zap',
          ruleId: alert.pluginid,
          ruleName: alert.name,
          severity: this.mapZapSeverity(alert.riskdesc),
          category: 'web-security',
          description: alert.desc,
          location: {
            file: instance.uri || alert.instances?.[0]?.uri || 'unknown',
            line: 1
          },
          cwe: alert.cweid ? [alert.cweid] : undefined,
          fix: alert.solution ? {
            suggestion: alert.solution,
            effort: 'medium'
          } : undefined,
          metadata: {
            method: instance.method,
            parameter: instance.param,
            attack: instance.attack,
            evidence: instance.evidence,
            reference: alert.reference
          }
        });
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Process Gitleaks (Secrets) results
   */
  private processGitleaksResults(result: any): VulnerabilityResult[] {
    if (!Array.isArray(result)) return [];
    
    return result.map((finding: any) => ({
      scanner: 'gitleaks',
      ruleId: finding.RuleID,
      ruleName: finding.RuleID,
      severity: 'high' as const,
      category: 'secrets',
      description: `Secret detected: ${finding.Description || finding.RuleID}`,
      location: {
        file: finding.File,
        line: finding.StartLine,
        column: finding.StartColumn,
        endLine: finding.EndLine,
        endColumn: finding.EndColumn
      },
      fix: {
        suggestion: 'Remove or rotate the exposed secret',
        effort: 'high'
      },
      metadata: {
        secret: finding.Secret ? '***REDACTED***' : undefined,
        commit: finding.Commit,
        author: finding.Author,
        email: finding.Email,
        date: finding.Date
      }
    }));
  }

  /**
   * Process Checkov (IaC) results
   */
  private processCheckovResults(result: any): VulnerabilityResult[] {
    const vulnerabilities: VulnerabilityResult[] = [];
    
    if (result.results?.failed_checks) {
      for (const check of result.results.failed_checks) {
        vulnerabilities.push({
          scanner: 'checkov',
          ruleId: check.check_id,
          ruleName: check.check_name,
          severity: this.mapCheckovSeverity(check.severity),
          category: 'infrastructure',
          description: check.check_name,
          location: {
            file: check.file_path,
            line: check.file_line_range?.[0]
          },
          fix: {
            suggestion: check.guideline || 'Review and fix the infrastructure configuration',
            effort: 'medium'
          },
          metadata: {
            resource: check.resource,
            checkType: check.check_type,
            guideline: check.guideline
          }
        });
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Process Trivy container results
   */
  private processTrivyContainerResults(result: any): VulnerabilityResult[] {
    // Similar to processTrivyResults but for container images
    return this.processTrivyResults(result);
  }

  /**
   * Process generic results for unknown scanners
   */
  private processGenericResults(result: any, scannerType: string): VulnerabilityResult[] {
    // Attempt to extract vulnerabilities from unknown format
    const vulnerabilities: VulnerabilityResult[] = [];
    
    if (Array.isArray(result)) {
      result.forEach((item, index) => {
        vulnerabilities.push({
          scanner: scannerType,
          ruleId: item.id || item.rule || `unknown-${index}`,
          ruleName: item.name || item.title || `Unknown Rule ${index}`,
          severity: 'medium',
          category: 'unknown',
          description: item.description || item.message || 'Unknown vulnerability',
          location: {
            file: item.file || item.path || 'unknown',
            line: item.line || 1
          }
        });
      });
    }
    
    return vulnerabilities;
  }

  /**
   * Generate summary from processed vulnerabilities
   */
  private generateSummary(vulnerabilities: VulnerabilityResult[]): ScanSummary {
    const summary: ScanSummary = {
      totalVulnerabilities: vulnerabilities.length,
      vulnerabilitiesBySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      vulnerabilitiesByScanner: {},
      vulnerabilitiesByCategory: {},
      timestamp: new Date().toISOString()
    };

    vulnerabilities.forEach(vuln => {
      // Count by severity
      summary.vulnerabilitiesBySeverity[vuln.severity]++;
      
      // Count by scanner
      summary.vulnerabilitiesByScanner[vuln.scanner] = 
        (summary.vulnerabilitiesByScanner[vuln.scanner] || 0) + 1;
      
      // Count by category
      summary.vulnerabilitiesByCategory[vuln.category] = 
        (summary.vulnerabilitiesByCategory[vuln.category] || 0) + 1;
    });

    return summary;
  }

  /**
   * Format results to specified format
   */
  async format(results: ProcessedResults | any[], format: string): Promise<string> {
    // If results is raw array, process it first
    let processedResults: ProcessedResults;
    if (Array.isArray(results)) {
      processedResults = await this.process(results);
    } else {
      processedResults = results;
    }

    switch (format.toLowerCase()) {
      case 'json':
        return JSON.stringify(processedResults, null, 2);
      case 'sarif':
        return this.formatSARIF(processedResults);
      case 'html':
        return this.formatHTML(processedResults);
      case 'csv':
        return this.formatCSV(processedResults);
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Format results as SARIF 2.1.0
   */
  private formatSARIF(results: ProcessedResults): string {
    const sarif = {
      $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'SecureScan Framework',
            version: '1.0.0',
            informationUri: 'https://github.com/securescan/framework'
          }
        },
        results: results.vulnerabilities.map(vuln => ({
          ruleId: vuln.ruleId,
          message: {
            text: vuln.description
          },
          level: this.mapSeverityToSarifLevel(vuln.severity),
          locations: [{
            physicalLocation: {
              artifactLocation: {
                uri: vuln.location.file
              },
              region: {
                startLine: vuln.location.line || 1,
                startColumn: vuln.location.column || 1,
                endLine: vuln.location.endLine,
                endColumn: vuln.location.endColumn
              }
            }
          }],
          properties: {
            scanner: vuln.scanner,
            category: vuln.category,
            cwe: vuln.cwe,
            cve: vuln.cve,
            fix: vuln.fix
          }
        }))
      }]
    };

    return JSON.stringify(sarif, null, 2);
  }

  /**
   * Format results as HTML report
   */
  private formatHTML(results: ProcessedResults): string {
    const { summary, vulnerabilities } = results;
    
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureScan Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #198754; }
        .vulnerabilities { margin-top: 30px; }
        .vulnerability { border: 1px solid #dee2e6; margin-bottom: 15px; border-radius: 6px; }
        .vulnerability-header { background: #f8f9fa; padding: 15px; border-bottom: 1px solid #dee2e6; }
        .vulnerability-body { padding: 15px; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: black; }
        .badge-low { background: #198754; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SecureScan Security Report</h1>
            <p>Generated on ${new Date(summary.timestamp).toLocaleString()}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div style="font-size: 2em; font-weight: bold;">${summary.totalVulnerabilities}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="severity-critical" style="font-size: 2em; font-weight: bold;">${summary.vulnerabilitiesBySeverity.critical}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="severity-high" style="font-size: 2em; font-weight: bold;">${summary.vulnerabilitiesBySeverity.high}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="severity-medium" style="font-size: 2em; font-weight: bold;">${summary.vulnerabilitiesBySeverity.medium}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="severity-low" style="font-size: 2em; font-weight: bold;">${summary.vulnerabilitiesBySeverity.low}</div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>Vulnerabilities</h2>
            ${vulnerabilities.map(vuln => `
                <div class="vulnerability">
                    <div class="vulnerability-header">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <h4 style="margin: 0;">${vuln.ruleName}</h4>
                            <span class="badge badge-${vuln.severity}">${vuln.severity.toUpperCase()}</span>
                        </div>
                        <div style="font-size: 0.9em; color: #6c757d; margin-top: 5px;">
                            ${vuln.scanner.toUpperCase()} • ${vuln.location.file}:${vuln.location.line || 1}
                        </div>
                    </div>
                    <div class="vulnerability-body">
                        <p>${vuln.description}</p>
                        ${vuln.fix ? `<div><strong>Fix:</strong> ${vuln.fix.suggestion}</div>` : ''}
                        ${vuln.cwe ? `<div><strong>CWE:</strong> ${vuln.cwe.join(', ')}</div>` : ''}
                        ${vuln.cve ? `<div><strong>CVE:</strong> ${vuln.cve.join(', ')}</div>` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
    </div>
</body>
</html>`;

    return html.trim();
  }

  /**
   * Format results as CSV
   */
  private formatCSV(results: ProcessedResults): string {
    const headers = [
      'Scanner',
      'Rule ID',
      'Rule Name',
      'Severity',
      'Category',
      'Description',
      'File',
      'Line',
      'CWE',
      'CVE',
      'Fix Suggestion'
    ];

    const rows = results.vulnerabilities.map(vuln => [
      vuln.scanner,
      vuln.ruleId,
      vuln.ruleName,
      vuln.severity,
      vuln.category,
      `"${vuln.description.replace(/"/g, '""')}"`,
      vuln.location.file,
      vuln.location.line || '',
      vuln.cwe?.join(';') || '',
      vuln.cve?.join(';') || '',
      vuln.fix ? `"${vuln.fix.suggestion.replace(/"/g, '""')}"` : ''
    ]);

    return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
  }

  // Severity mapping helpers
  private mapSemgrepSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity?.toLowerCase()) {
      case 'error': return 'high';
      case 'warning': return 'medium';
      case 'info': return 'low';
      default: return 'medium';
    }
  }

  private mapTrivySeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return 'medium';
    }
  }

  private mapZapSeverity(riskDesc: string): 'low' | 'medium' | 'high' | 'critical' {
    const severity = riskDesc?.split(' ')[0]?.toLowerCase();
    switch (severity) {
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      case 'informational': return 'low';
      default: return 'medium';
    }
  }

  private mapCheckovSeverity(severity: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return 'medium';
    }
  }

  private mapSeverityToSarifLevel(severity: string): string {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'note';
      default: return 'warning';
    }
  }
}