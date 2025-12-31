#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import ora from 'ora';
import fs from 'fs/promises';
import path from 'path';
import { z } from 'zod';
import axios from 'axios';
import { ConfigManager } from '../lib/config-manager.js';
import { APIClient } from '../lib/api-client.js';
import { Logger } from '../lib/logger.js';
import { ScanResultsProcessor } from '../lib/scan-results-processor.js';

/**
 * Scan Command - Execute security scans locally or remotely
 * 
 * This command handles both local scanning (using Docker containers)
 * and remote scanning (via SecureScan Platform API).
 * 
 * Supported scanner types:
 * - SAST: Static Application Security Testing (Semgrep)
 * - SCA: Software Composition Analysis (Trivy)
 * - DAST: Dynamic Application Security Testing (OWASP ZAP)
 * - Secrets: Secret detection (Gitleaks)
 * - IaC: Infrastructure as Code scanning (Checkov)
 * - Container: Container image scanning (Trivy)
 */

// Validation schemas
const ScanOptionsSchema = z.object({
  type: z.array(z.enum(['sast', 'sca', 'dast', 'secrets', 'iac', 'container', 'all'])).optional(),
  target: z.string().optional(),
  output: z.string().optional(),
  format: z.enum(['json', 'sarif', 'html', 'csv']).default('json'),
  severity: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
  exclude: z.array(z.string()).optional(),
  config: z.string().optional(),
  projectId: z.string().optional(),
  wait: z.boolean().default(false),
  timeout: z.number().default(3600), // 1 hour in seconds
  parallel: z.boolean().default(true),
  local: z.boolean().default(false),
  verbose: z.boolean().default(false)
});

type ScanOptions = z.infer<typeof ScanOptionsSchema>;

interface ScanResult {
  scanId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  results?: any;
  vulnerabilities?: number;
  errors?: string[];
}

export function createScanCommand(): Command {
  const command = new Command('scan')
    .description('Execute security scans on your codebase')
    .usage('[options] [target]')
    .argument('[target]', 'Target directory, file, or URL to scan', process.cwd())
    .option('-t, --type <types...>', 'Scanner types to run (sast,sca,dast,secrets,iac,container,all)', ['all'])
    .option('-o, --output <path>', 'Output file path for scan results')
    .option('-f, --format <format>', 'Output format (json,sarif,html,csv)', 'json')
    .option('-s, --severity <levels...>', 'Filter by severity levels (low,medium,high,critical)')
    .option('-e, --exclude <patterns...>', 'Exclude patterns (glob patterns)')
    .option('-c, --config <path>', 'Custom configuration file path')
    .option('-p, --project-id <id>', 'Project ID for remote scanning')
    .option('-w, --wait', 'Wait for scan completion (remote scans)', false)
    .option('--timeout <seconds>', 'Scan timeout in seconds', '3600')
    .option('--no-parallel', 'Disable parallel scanning')
    .option('--local', 'Force local scanning (requires Docker)', false)
    .option('--verbose', 'Enable verbose output', false)
    .action(async (target: string, options: any) => {
      const logger = new Logger(options.verbose);
      
      try {
        // Validate and parse options
        const scanOptions = ScanOptionsSchema.parse({
          ...options,
          timeout: parseInt(options.timeout, 10),
          type: options.type === 'all' ? ['sast', 'sca', 'dast', 'secrets', 'iac', 'container'] : options.type
        });

        logger.info(`Starting security scan for: ${chalk.cyan(target)}`);
        
        // Initialize scan executor
        const executor = new ScanExecutor(logger);
        
        // Execute scan
        const result = await executor.execute(target, scanOptions);
        
        // Process and display results
        await handleScanResults(result, scanOptions, logger);
        
      } catch (error) {
        logger.error('Scan failed:', error);
        process.exit(1);
      }
    });

  // Add subcommands
  command.addCommand(createStatusCommand());
  command.addCommand(createListCommand());
  command.addCommand(createCancelCommand());

  return command;
}

/**
 * Scan Executor - Handles both local and remote scan execution
 */
class ScanExecutor {
  private configManager: ConfigManager;
  private apiClient: APIClient;

  constructor(private logger: Logger) {
    this.configManager = new ConfigManager();
    this.apiClient = new APIClient();
  }

  async execute(target: string, options: ScanOptions): Promise<ScanResult> {
    // Determine scan mode (local vs remote)
    const useLocal = options.local || !await this.isRemoteConfigured();
    
    if (useLocal) {
      return this.executeLocalScan(target, options);
    } else {
      return this.executeRemoteScan(target, options);
    }
  }

  private async isRemoteConfigured(): Promise<boolean> {
    try {
      const config = await this.configManager.getConfig();
      return !!(config.apiUrl && config.apiKey);
    } catch {
      return false;
    }
  }

  private async executeLocalScan(target: string, options: ScanOptions): Promise<ScanResult> {
    this.logger.info('🔧 Executing local scan using Docker containers...');
    
    const spinner = ora('Preparing scan environment...').start();
    
    try {
      // Validate Docker availability
      await this.validateDockerEnvironment();
      spinner.text = 'Docker environment validated';
      
      // Prepare scan configuration
      const scanConfig = await this.prepareScanConfig(target, options);
      spinner.text = 'Scan configuration prepared';
      
      // Execute scanners in parallel or sequence
      const scanResults: any[] = [];
      
      if (options.parallel) {
        spinner.text = 'Running scanners in parallel...';
        const promises = options.type!.map(scannerType => 
          this.runLocalScanner(scannerType, target, scanConfig, options)
        );
        const results = await Promise.allSettled(promises);
        
        results.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            scanResults.push(result.value);
          } else {
            this.logger.warn(`Scanner ${options.type![index]} failed:`, result.reason);
          }
        });
      } else {
        for (const scannerType of options.type!) {
          spinner.text = `Running ${scannerType.toUpperCase()} scanner...`;
          try {
            const result = await this.runLocalScanner(scannerType, target, scanConfig, options);
            scanResults.push(result);
          } catch (error) {
            this.logger.warn(`Scanner ${scannerType} failed:`, error);
          }
        }
      }
      
      spinner.succeed('Local scan completed');
      
      // Aggregate results
      return {
        scanId: `local-${Date.now()}`,
        status: 'completed',
        results: scanResults,
        vulnerabilities: this.countVulnerabilities(scanResults)
      };
      
    } catch (error) {
      spinner.fail('Local scan failed');
      throw error;
    }
  }

  private async executeRemoteScan(target: string, options: ScanOptions): Promise<ScanResult> {
    this.logger.info('☁️  Executing remote scan via SecureScan Platform...');
    
    const spinner = ora('Initiating remote scan...').start();
    
    try {
      // Get or create project
      const projectId = options.projectId || await this.getOrCreateProject(target);
      
      // Start scan
      const scanResponse = await this.apiClient.post('/scans', {
        projectId,
        name: `CLI Scan - ${new Date().toISOString()}`,
        scanners: options.type,
        configuration: await this.prepareRemoteScanConfig(options)
      });
      
      const scanId = scanResponse.data.id;
      spinner.text = `Scan started (ID: ${scanId})`;
      
      if (options.wait) {
        return this.waitForRemoteScan(scanId, spinner);
      } else {
        spinner.succeed(`Remote scan initiated: ${scanId}`);
        return {
          scanId,
          status: 'pending'
        };
      }
      
    } catch (error) {
      spinner.fail('Remote scan failed');
      throw error;
    }
  }

  private async runLocalScanner(
    scannerType: string, 
    target: string, 
    config: any, 
    options: ScanOptions
  ): Promise<any> {
    const dockerImages = {
      sast: 'returntocorp/semgrep:latest',
      sca: 'aquasec/trivy:latest',
      dast: 'owasp/zap2docker-stable:latest',
      secrets: 'zricethezav/gitleaks:latest',
      iac: 'bridgecrew/checkov:latest',
      container: 'aquasec/trivy:latest'
    };

    const image = dockerImages[scannerType as keyof typeof dockerImages];
    if (!image) {
      throw new Error(`Unsupported scanner type: ${scannerType}`);
    }

    // Build Docker command based on scanner type
    const dockerCmd = this.buildDockerCommand(scannerType, image, target, config, options);
    
    // Execute Docker command
    const { execSync } = await import('child_process');
    const output = execSync(dockerCmd, { encoding: 'utf-8' });
    
    // Parse scanner output
    return this.parseScannerOutput(scannerType, output);
  }

  private buildDockerCommand(
    scannerType: string, 
    image: string, 
    target: string, 
    config: any, 
    options: ScanOptions
  ): string {
    const baseCmd = `docker run --rm -v "${target}:/app"`;
    
    switch (scannerType) {
      case 'sast':
        return `${baseCmd} ${image} --config=auto --json /app`;
      
      case 'sca':
        return `${baseCmd} ${image} fs --format json /app`;
      
      case 'secrets':
        return `${baseCmd} ${image} detect --source /app --format json`;
      
      case 'iac':
        return `${baseCmd} ${image} --framework all --output json /app`;
      
      case 'container':
        return `${baseCmd} ${image} image --format json ${target}`;
      
      case 'dast':
        const targetUrl = config.targetUrl || 'http://localhost:8080';
        return `${baseCmd} ${image} zap-baseline.py -t ${targetUrl} -J /app/zap-report.json`;
      
      default:
        throw new Error(`Unknown scanner type: ${scannerType}`);
    }
  }

  private async validateDockerEnvironment(): Promise<void> {
    try {
      const { execSync } = await import('child_process');
      execSync('docker --version', { stdio: 'ignore' });
    } catch {
      throw new Error('Docker is not available. Please install Docker to run local scans.');
    }
  }

  private async prepareScanConfig(target: string, options: ScanOptions): Promise<any> {
    const config: any = {
      target,
      scanners: options.type,
      severity: options.severity || ['medium', 'high', 'critical'],
      exclude: options.exclude || []
    };

    // Load custom config if specified
    if (options.config) {
      try {
        const customConfig = JSON.parse(await fs.readFile(options.config, 'utf-8'));
        Object.assign(config, customConfig);
      } catch (error) {
        this.logger.warn(`Failed to load custom config: ${error}`);
      }
    }

    return config;
  }

  private async prepareRemoteScanConfig(options: ScanOptions): Promise<any> {
    return {
      severity: options.severity || ['medium', 'high', 'critical'],
      exclude: options.exclude || [],
      timeout: options.timeout,
      parallel: options.parallel
    };
  }

  private async getOrCreateProject(target: string): Promise<string> {
    // Try to find existing project based on target
    const projects = await this.apiClient.get('/projects');
    const existingProject = projects.data.find((p: any) => 
      p.name === path.basename(target) || p.repositoryUrl?.includes(target)
    );

    if (existingProject) {
      return existingProject.id;
    }

    // Create new project
    const newProject = await this.apiClient.post('/projects', {
      name: path.basename(target),
      description: `Auto-created project for ${target}`,
      repositoryUrl: target.startsWith('http') ? target : undefined
    });

    return newProject.data.id;
  }

  private async waitForRemoteScan(scanId: string, spinner: ora.Ora): Promise<ScanResult> {
    const maxAttempts = 60; // 10 minutes with 10-second intervals
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const response = await this.apiClient.get(`/scans/${scanId}`);
        const scan = response.data;

        spinner.text = `Scan ${scan.status} (${attempts * 10}s elapsed)`;

        if (scan.status === 'completed') {
          spinner.succeed('Remote scan completed');
          return {
            scanId,
            status: 'completed',
            results: scan.results,
            vulnerabilities: scan.vulnerabilityCount
          };
        }

        if (scan.status === 'failed') {
          spinner.fail('Remote scan failed');
          return {
            scanId,
            status: 'failed',
            errors: scan.errors
          };
        }

        await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
        attempts++;

      } catch (error) {
        this.logger.warn('Error checking scan status:', error);
        attempts++;
      }
    }

    spinner.warn('Scan timeout reached');
    return {
      scanId,
      status: 'running'
    };
  }

  private parseScannerOutput(scannerType: string, output: string): any {
    try {
      // Most scanners output JSON, but we may need custom parsing
      return JSON.parse(output);
    } catch {
      // If JSON parsing fails, return raw output
      return {
        scannerType,
        rawOutput: output,
        timestamp: new Date().toISOString()
      };
    }
  }

  private countVulnerabilities(results: any[]): number {
    return results.reduce((total, result) => {
      if (result.vulnerabilities) {
        return total + result.vulnerabilities.length;
      }
      if (result.results) {
        return total + result.results.length;
      }
      return total;
    }, 0);
  }
}

/**
 * Handle and display scan results
 */
async function handleScanResults(
  result: ScanResult, 
  options: ScanOptions, 
  logger: Logger
): Promise<void> {
  logger.info('\n📊 Scan Results Summary:');
  logger.info(`Scan ID: ${chalk.cyan(result.scanId)}`);
  logger.info(`Status: ${getStatusColor(result.status)}`);

  if (result.vulnerabilities !== undefined) {
    logger.info(`Vulnerabilities: ${chalk.red(result.vulnerabilities)}`);
  }

  if (result.errors?.length) {
    logger.warn(`Errors: ${result.errors.length}`);
    result.errors.forEach(error => logger.warn(`  - ${error}`));
  }

  // Save results to file if requested
  if (options.output && result.results) {
    await saveResults(result, options, logger);
  }

  // Display interactive results if in terminal
  if (result.results && !options.output) {
    await displayInteractiveResults(result.results, logger);
  }
}

function getStatusColor(status: string): string {
  switch (status) {
    case 'completed': return chalk.green(status);
    case 'failed': return chalk.red(status);
    case 'running': return chalk.yellow(status);
    case 'pending': return chalk.blue(status);
    default: return status;
  }
}

async function saveResults(
  result: ScanResult, 
  options: ScanOptions, 
  logger: Logger
): Promise<void> {
  try {
    const processor = new ScanResultsProcessor();
    const formattedResults = await processor.format(result.results!, options.format);
    
    await fs.writeFile(options.output!, formattedResults);
    logger.success(`Results saved to: ${chalk.cyan(options.output!)}`);
  } catch (error) {
    logger.error(`Failed to save results: ${error}`);
  }
}

async function displayInteractiveResults(results: any[], logger: Logger): Promise<void> {
  if (!results.length) {
    logger.info(chalk.green('✅ No vulnerabilities found!'));
    return;
  }

  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to do with the results?',
      choices: [
        'View summary',
        'View detailed results',
        'Save to file',
        'Exit'
      ]
    }
  ]);

  switch (action) {
    case 'View summary':
      displayResultsSummary(results, logger);
      break;
    case 'View detailed results':
      await displayDetailedResults(results, logger);
      break;
    case 'Save to file':
      await promptSaveResults(results, logger);
      break;
  }
}

function displayResultsSummary(results: any[], logger: Logger): void {
  const summary = results.reduce((acc, result) => {
    const scannerType = result.scannerType || 'unknown';
    const vulnCount = result.vulnerabilities?.length || result.results?.length || 0;
    acc[scannerType] = (acc[scannerType] || 0) + vulnCount;
    return acc;
  }, {});

  logger.info('\n📈 Vulnerability Summary by Scanner:');
  Object.entries(summary).forEach(([scanner, count]) => {
    logger.info(`  ${scanner.toUpperCase()}: ${chalk.red(count)}`);
  });
}

async function displayDetailedResults(results: any[], logger: Logger): Promise<void> {
  // Implementation for detailed results display
  // This would show individual vulnerabilities with severity, location, etc.
  logger.info('Detailed results display not implemented yet');
}

async function promptSaveResults(results: any[], logger: Logger): Promise<void> {
  const { filename, format } = await inquirer.prompt([
    {
      type: 'input',
      name: 'filename',
      message: 'Enter filename:',
      default: `scan-results-${Date.now()}`
    },
    {
      type: 'list',
      name: 'format',
      message: 'Select format:',
      choices: ['json', 'sarif', 'html', 'csv']
    }
  ]);

  const processor = new ScanResultsProcessor();
  const formattedResults = await processor.format(results, format);
  const fullPath = `${filename}.${format}`;
  
  await fs.writeFile(fullPath, formattedResults);
  logger.success(`Results saved to: ${chalk.cyan(fullPath)}`);
}

// Subcommands
function createStatusCommand(): Command {
  return new Command('status')
    .description('Check the status of a running scan')
    .argument('<scan-id>', 'Scan ID to check')
    .action(async (scanId: string) => {
      const logger = new Logger();
      
      try {
        const apiClient = new APIClient();
        const response = await apiClient.get(`/scans/${scanId}`);
        const scan = response.data;

        logger.info(`Scan Status: ${getStatusColor(scan.status)}`);
        logger.info(`Progress: ${scan.progress || 0}%`);
        
        if (scan.vulnerabilityCount !== undefined) {
          logger.info(`Vulnerabilities: ${chalk.red(scan.vulnerabilityCount)}`);
        }
        
      } catch (error) {
        logger.error('Failed to get scan status:', error);
        process.exit(1);
      }
    });
}

function createListCommand(): Command {
  return new Command('list')
    .description('List recent scans')
    .option('-p, --project-id <id>', 'Filter by project ID')
    .option('-l, --limit <number>', 'Number of scans to show', '10')
    .action(async (options: any) => {
      const logger = new Logger();
      
      try {
        const apiClient = new APIClient();
        const params = new URLSearchParams();
        
        if (options.projectId) params.append('projectId', options.projectId);
        params.append('limit', options.limit);
        
        const response = await apiClient.get(`/scans?${params}`);
        const scans = response.data;

        if (!scans.length) {
          logger.info('No scans found');
          return;
        }

        logger.info('\n📋 Recent Scans:');
        scans.forEach((scan: any) => {
          logger.info(`  ${scan.id} - ${getStatusColor(scan.status)} - ${scan.createdAt}`);
        });
        
      } catch (error) {
        logger.error('Failed to list scans:', error);
        process.exit(1);
      }
    });
}

function createCancelCommand(): Command {
  return new Command('cancel')
    .description('Cancel a running scan')
    .argument('<scan-id>', 'Scan ID to cancel')
    .action(async (scanId: string) => {
      const logger = new Logger();
      
      try {
        const apiClient = new APIClient();
        await apiClient.delete(`/scans/${scanId}`);
        
        logger.success(`Scan ${scanId} cancelled successfully`);
        
      } catch (error) {
        logger.error('Failed to cancel scan:', error);
        process.exit(1);
      }
    });
}