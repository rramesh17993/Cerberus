#!/usr/bin/env node

/**
 * 🚀 SecureScan Framework CLI - Entry Point
 * 
 * Command-line interface for the SecureScan Framework
 * 
 * Features:
 * - Local and remote security scanning
 * - Project management
 * - CI/CD integration
 * - Report generation
 * - Configuration management
 * - Interactive scan setup
 * 
 * Author: SecureScan Team
 */

import { Command } from 'commander';
import chalk from 'chalk';
import updateNotifier from 'update-notifier';
import { config } from '@/config';
import { logger } from '@/utils/logger';
import { CLIError } from '@/utils/errors';

// Import commands
import { scanCommand } from '@/commands/scan';
import { projectCommand } from '@/commands/project';
import { configCommand } from '@/commands/config';
import { authCommand } from '@/commands/auth';
import { reportCommand } from '@/commands/report';
import { initCommand } from '@/commands/init';
import { versionCommand } from '@/commands/version';

// Package information
const pkg = require('../../package.json');

// =============================================================================
// 🔔 UPDATE NOTIFICATION
// =============================================================================

// Check for updates (async, non-blocking)
const notifier = updateNotifier({
  pkg,
  updateCheckInterval: 1000 * 60 * 60 * 24 // Check daily
});

if (notifier.update && notifier.update.latest !== pkg.version) {
  const updateMessage = [
    '',
    chalk.yellow('┌' + '─'.repeat(60) + '┐'),
    chalk.yellow('│') + ' ' + chalk.bold('Update available:') + ' ' + 
    chalk.gray(pkg.version) + ' → ' + chalk.green(notifier.update.latest) + ' '.repeat(20) + chalk.yellow('│'),
    chalk.yellow('│') + ' ' + chalk.gray('Run ') + chalk.cyan('npm install -g securescan-cli') + 
    ' to update' + ' '.repeat(11) + chalk.yellow('│'),
    chalk.yellow('└' + '─'.repeat(60) + '┘'),
    ''
  ].join('\n');
  
  console.log(updateMessage);
}

// =============================================================================
// 🛠️ CLI PROGRAM SETUP
// =============================================================================

const program = new Command();

program
  .name('securescan')
  .description('SecureScan Framework CLI - Comprehensive security scanning tool')
  .version(pkg.version, '-v, --version', 'display version number')
  .helpOption('-h, --help', 'display help for command')
  .addHelpText('before', chalk.bold.blue('🛡️  SecureScan Framework CLI\n'))
  .addHelpText('after', `
${chalk.bold('Examples:')}
  ${chalk.cyan('securescan scan')}                    Start interactive scan
  ${chalk.cyan('securescan scan --type sast')}       Run SAST scan only
  ${chalk.cyan('securescan scan --all')}             Run all scanners
  ${chalk.cyan('securescan project create')}         Create new project
  ${chalk.cyan('securescan auth login')}             Login to SecureScan platform
  ${chalk.cyan('securescan init')}                   Initialize project configuration

${chalk.bold('Documentation:')}
  ${chalk.gray('https://docs.securescan.io')}

${chalk.bold('Support:')}
  ${chalk.gray('https://github.com/securescan/framework/issues')}
`);

// =============================================================================
// 🔧 GLOBAL OPTIONS
// =============================================================================

program
  .option('-c, --config <path>', 'configuration file path', config.defaultConfigPath)
  .option('-v, --verbose', 'enable verbose logging')
  .option('-q, --quiet', 'suppress all output except errors')
  .option('--no-color', 'disable colored output')
  .option('--api-url <url>', 'SecureScan API URL', config.defaultApiUrl)
  .option('--timeout <seconds>', 'request timeout in seconds', '300')
  .option('--retry <count>', 'number of retries for failed requests', '3');

// =============================================================================
// 📝 COMMAND REGISTRATION
// =============================================================================

// Core commands
program.addCommand(scanCommand);
program.addCommand(projectCommand);
program.addCommand(authCommand);
program.addCommand(configCommand);
program.addCommand(reportCommand);
program.addCommand(initCommand);
program.addCommand(versionCommand);

// =============================================================================
// 🎯 COMMAND EXECUTION
// =============================================================================

async function main() {
  try {
    // Configure logger based on global options
    const options = program.opts();
    
    if (options.quiet) {
      logger.level = 'error';
    } else if (options.verbose) {
      logger.level = 'debug';
    }

    if (options.noColor) {
      chalk.level = 0;
    }

    // Update global config with CLI options
    if (options.config) {
      config.configPath = options.config;
    }
    if (options.apiUrl) {
      config.apiUrl = options.apiUrl;
    }
    if (options.timeout) {
      config.timeout = parseInt(options.timeout, 10) * 1000;
    }
    if (options.retry) {
      config.retryCount = parseInt(options.retry, 10);
    }

    // Load configuration
    await config.load();

    // Parse and execute command
    await program.parseAsync(process.argv);

  } catch (error) {
    await handleError(error);
  }
}

// =============================================================================
// 🚨 ERROR HANDLING
// =============================================================================

async function handleError(error: unknown): Promise<void> {
  let exitCode = 1;
  
  if (error instanceof CLIError) {
    // Handle known CLI errors
    logger.error(error.message);
    if (error.details) {
      logger.debug('Error details:', error.details);
    }
    exitCode = error.exitCode;
  } else if (error instanceof Error) {
    // Handle generic errors
    logger.error('An unexpected error occurred:', error.message);
    logger.debug('Stack trace:', error.stack);
  } else {
    // Handle unknown errors
    logger.error('An unknown error occurred:', String(error));
  }

  // Show help for command errors
  if (error instanceof CLIError && error.showHelp) {
    console.log('\n' + program.helpInformation());
  }

  process.exit(exitCode);
}

// =============================================================================
// 🔧 PROCESS HANDLING
// =============================================================================

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception:', error.message);
  logger.debug('Stack trace:', error.stack);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled rejection:', reason);
  process.exit(1);
});

// Handle SIGINT (Ctrl+C)
process.on('SIGINT', () => {
  logger.info('\n👋 Goodbye!');
  process.exit(0);
});

// Handle SIGTERM
process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

// =============================================================================
// 🚀 START APPLICATION
// =============================================================================

// Check Node.js version
const nodeVersion = process.version;
const requiredVersion = '18.0.0';

if (require('semver').lt(nodeVersion, requiredVersion)) {
  console.error(
    chalk.red('✗') + ' ' +
    chalk.bold('Node.js version requirement not met!') + '\n' +
    '  Required: ' + chalk.green('>=') + requiredVersion + '\n' +
    '  Current:  ' + chalk.red(nodeVersion) + '\n\n' +
    'Please upgrade Node.js to continue.'
  );
  process.exit(1);
}

// Start the CLI
if (require.main === module) {
  main().catch(handleError);
}

// Export for testing
export { program, main };