#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs/promises';
import path from 'path';
import { Logger } from '../lib/logger.js';

/**
 * Report Command - Generate and manage scan reports
 * 
 * Provides comprehensive reporting capabilities including:
 * - Generating reports from scan results
 * - Converting between formats
 * - Customizing report templates
 * - Combining multiple scan results
 */

export function createReportCommand(): Command {
  const command = new Command('report')
    .description('Generate and manage scan reports')
    .usage('<subcommand> [options]');

  // Add subcommands
  command.addCommand(createGenerateCommand());
  command.addCommand(createConvertCommand());
  command.addCommand(createTemplateCommand());
  command.addCommand(createCombineCommand());

  return command;
}

/**
 * Generate report command
 */
function createGenerateCommand(): Command {
  return new Command('generate')
    .description('Generate report from scan results')
    .argument('<input>', 'Input scan results file')
    .option('-o, --output <path>', 'Output file path')
    .option('-f, --format <format>', 'Output format (json, sarif, html, csv, pdf)', 'html')
    .option('-t, --template <template>', 'Report template')
    .option('--title <title>', 'Report title')
    .option('--include-summary', 'Include executive summary', true)
    .option('--include-details', 'Include vulnerability details', true)
    .option('--include-remediation', 'Include remediation guidance', true)
    .action(async (input: string, options: any) => {
      const logger = new Logger();

      try {
        // Read input file
        const inputPath = path.resolve(input);
        const resultsData = await fs.readFile(inputPath, 'utf-8');
        const results = JSON.parse(resultsData);

        // Generate report
        const reportGenerator = new ReportGenerator(logger);
        const report = await reportGenerator.generate(results, {
          format: options.format,
          template: options.template,
          title: options.title || 'Security Scan Report',
          includeSummary: options.includeSummary,
          includeDetails: options.includeDetails,
          includeRemediation: options.includeRemediation
        });

        // Save report
        const outputPath = options.output || `report.${options.format}`;
        await fs.writeFile(path.resolve(outputPath), report);

        logger.success(`✅ Report generated: ${chalk.cyan(outputPath)}`);

      } catch (error) {
        logger.error('Failed to generate report:', error);
        process.exit(1);
      }
    });
}

/**
 * Convert format command
 */
function createConvertCommand(): Command {
  return new Command('convert')
    .description('Convert report between formats')
    .argument('<input>', 'Input file')
    .option('-f, --from <format>', 'Source format (auto-detect if not specified)')
    .option('-t, --to <format>', 'Target format', 'html')
    .option('-o, --output <path>', 'Output file path')
    .action(async (input: string, options: any) => {
      const logger = new Logger();

      try {
        const inputPath = path.resolve(input);
        const outputPath = options.output || `converted.${options.to}`;

        const converter = new FormatConverter(logger);
        await converter.convert(inputPath, outputPath, {
          from: options.from,
          to: options.to
        });

        logger.success(`✅ Converted to: ${chalk.cyan(outputPath)}`);

      } catch (error) {
        logger.error('Failed to convert report:', error);
        process.exit(1);
      }
    });
}

/**
 * Template management command
 */
function createTemplateCommand(): Command {
  const command = new Command('template')
    .description('Manage report templates');

  command
    .command('list')
    .description('List available templates')
    .action(async () => {
      const logger = new Logger();
      const templateManager = new TemplateManager(logger);
      const templates = await templateManager.listTemplates();

      logger.info('\n📄 Available Report Templates:');
      templates.forEach(template => {
        logger.info(`  ${template.name} - ${template.description}`);
      });
    });

  command
    .command('show')
    .description('Show template details')
    .argument('<name>', 'Template name')
    .action(async (name: string) => {
      const logger = new Logger();
      const templateManager = new TemplateManager(logger);
      const template = await templateManager.getTemplate(name);

      logger.info(`\n📄 Template: ${chalk.cyan(template.name)}`);
      logger.info(`Description: ${template.description}`);
      logger.info(`Format: ${template.format}`);
      logger.info(`Version: ${template.version}`);
    });

  return command;
}

/**
 * Combine reports command
 */
function createCombineCommand(): Command {
  return new Command('combine')
    .description('Combine multiple scan results into one report')
    .argument('<files...>', 'Input scan result files')
    .option('-o, --output <path>', 'Output file path', 'combined-report.html')
    .option('-f, --format <format>', 'Output format', 'html')
    .option('--title <title>', 'Report title', 'Combined Security Report')
    .action(async (files: string[], options: any) => {
      const logger = new Logger();

      try {
        const combiner = new ReportCombiner(logger);
        const combinedResults = await combiner.combine(files);

        const reportGenerator = new ReportGenerator(logger);
        const report = await reportGenerator.generate(combinedResults, {
          format: options.format,
          title: options.title
        });

        await fs.writeFile(path.resolve(options.output), report);
        logger.success(`✅ Combined report generated: ${chalk.cyan(options.output)}`);

      } catch (error) {
        logger.error('Failed to combine reports:', error);
        process.exit(1);
      }
    });
}

/**
 * Report Generator class
 */
class ReportGenerator {
  constructor(private logger: Logger) {}

  async generate(results: any, options: any): Promise<string> {
    switch (options.format.toLowerCase()) {
      case 'html':
        return this.generateHTML(results, options);
      case 'pdf':
        return this.generatePDF(results, options);
      case 'json':
        return this.generateJSON(results, options);
      case 'csv':
        return this.generateCSV(results, options);
      case 'sarif':
        return this.generateSARIF(results, options);
      default:
        throw new Error(`Unsupported format: ${options.format}`);
    }
  }

  private async generateHTML(results: any, options: any): Promise<string> {
    // Implementation would generate HTML report
    return `<html><body><h1>${options.title}</h1><p>Report content...</p></body></html>`;
  }

  private async generatePDF(results: any, options: any): Promise<string> {
    // Implementation would generate PDF using puppeteer or similar
    throw new Error('PDF generation not implemented yet');
  }

  private async generateJSON(results: any, options: any): Promise<string> {
    return JSON.stringify(results, null, 2);
  }

  private async generateCSV(results: any, options: any): Promise<string> {
    // Implementation would generate CSV format
    return 'CSV content...';
  }

  private async generateSARIF(results: any, options: any): Promise<string> {
    // Implementation would generate SARIF format
    return JSON.stringify({
      version: '2.1.0',
      runs: []
    }, null, 2);
  }
}

/**
 * Format Converter class
 */
class FormatConverter {
  constructor(private logger: Logger) {}

  async convert(inputPath: string, outputPath: string, options: any): Promise<void> {
    // Read input file
    const inputData = await fs.readFile(inputPath, 'utf-8');
    
    // Auto-detect format if not specified
    const fromFormat = options.from || this.detectFormat(inputData);
    
    // Parse input
    const parsedData = this.parseFormat(inputData, fromFormat);
    
    // Generate output
    const generator = new ReportGenerator(this.logger);
    const output = await generator.generate(parsedData, { format: options.to });
    
    // Write output
    await fs.writeFile(outputPath, output);
  }

  private detectFormat(data: string): string {
    try {
      const parsed = JSON.parse(data);
      if (parsed.version && parsed.$schema) return 'sarif';
      if (parsed.vulnerabilities || parsed.results) return 'json';
    } catch {
      // Not JSON
    }
    
    if (data.includes('<html>')) return 'html';
    if (data.includes(',')) return 'csv';
    
    return 'unknown';
  }

  private parseFormat(data: string, format: string): any {
    switch (format) {
      case 'json':
      case 'sarif':
        return JSON.parse(data);
      case 'csv':
        return this.parseCSV(data);
      default:
        throw new Error(`Cannot parse format: ${format}`);
    }
  }

  private parseCSV(data: string): any {
    // Simple CSV parser implementation
    const lines = data.split('\n');
    const headers = lines[0].split(',');
    const rows = lines.slice(1).map(line => {
      const values = line.split(',');
      const obj: any = {};
      headers.forEach((header, index) => {
        obj[header.trim()] = values[index]?.trim();
      });
      return obj;
    });
    
    return {
      vulnerabilities: rows.filter(row => Object.values(row).some(v => v))
    };
  }
}

/**
 * Template Manager class
 */
class TemplateManager {
  constructor(private logger: Logger) {}

  async listTemplates(): Promise<any[]> {
    return [
      {
        name: 'default',
        description: 'Default SecureScan report template',
        format: 'html',
        version: '1.0.0'
      },
      {
        name: 'executive',
        description: 'Executive summary template',
        format: 'html',
        version: '1.0.0'
      },
      {
        name: 'technical',
        description: 'Technical detailed report template',
        format: 'html',
        version: '1.0.0'
      }
    ];
  }

  async getTemplate(name: string): Promise<any> {
    const templates = await this.listTemplates();
    const template = templates.find(t => t.name === name);
    
    if (!template) {
      throw new Error(`Template not found: ${name}`);
    }
    
    return template;
  }
}

/**
 * Report Combiner class
 */
class ReportCombiner {
  constructor(private logger: Logger) {}

  async combine(files: string[]): Promise<any> {
    const allResults: any[] = [];
    
    for (const file of files) {
      try {
        const data = await fs.readFile(path.resolve(file), 'utf-8');
        const results = JSON.parse(data);
        allResults.push(results);
      } catch (error) {
        this.logger.warn(`Failed to read file ${file}:`, error);
      }
    }
    
    // Combine all vulnerabilities
    const combinedVulnerabilities: any[] = [];
    let totalScans = 0;
    
    for (const result of allResults) {
      if (result.vulnerabilities) {
        combinedVulnerabilities.push(...result.vulnerabilities);
      }
      totalScans++;
    }
    
    // Generate combined summary
    const summary = {
      totalVulnerabilities: combinedVulnerabilities.length,
      totalScans,
      vulnerabilitiesBySeverity: this.countBySeverity(combinedVulnerabilities),
      timestamp: new Date().toISOString()
    };
    
    return {
      summary,
      vulnerabilities: combinedVulnerabilities,
      metadata: {
        combined: true,
        sourceFiles: files,
        version: '1.0.0'
      }
    };
  }

  private countBySeverity(vulnerabilities: any[]): any {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    
    for (const vuln of vulnerabilities) {
      const severity = vuln.severity?.toLowerCase() || 'medium';
      if (counts.hasOwnProperty(severity)) {
        counts[severity as keyof typeof counts]++;
      }
    }
    
    return counts;
  }
}