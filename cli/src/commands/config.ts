#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import fs from 'fs/promises';
import path from 'path';
import { z } from 'zod';
import { ConfigManager } from '../lib/config-manager.js';
import { Logger } from '../lib/logger.js';

/**
 * Config Command - Manage CLI configuration
 * 
 * Provides comprehensive configuration management including:
 * - Setting scanner defaults
 * - Managing user preferences
 * - Importing/exporting configuration
 * - Resetting to defaults
 * - Interactive configuration wizard
 */

// Validation schemas
const ScannerConfigSchema = z.object({
  scanners: z.array(z.enum(['sast', 'sca', 'dast', 'secrets', 'iac', 'container'])).min(1),
  severity: z.array(z.enum(['low', 'medium', 'high', 'critical'])).min(1),
  format: z.enum(['json', 'sarif', 'html', 'csv']),
  timeout: z.number().min(60).max(7200) // 1 minute to 2 hours
});

const PreferencesConfigSchema = z.object({
  colorOutput: z.boolean(),
  verboseLogging: z.boolean(),
  autoUpdate: z.boolean()
});

export function createConfigCommand(): Command {
  const command = new Command('config')
    .description('Manage CLI configuration')
    .usage('<subcommand> [options]');

  // Add subcommands
  command.addCommand(createShowCommand());
  command.addCommand(createSetCommand());
  command.addCommand(createDefaultsCommand());
  command.addCommand(createPreferencesCommand());
  command.addCommand(createImportCommand());
  command.addCommand(createExportCommand());
  command.addCommand(createResetCommand());
  command.addCommand(createWizardCommand());

  return command;
}

/**
 * Show configuration command
 */
function createShowCommand(): Command {
  return new Command('show')
    .alias('get')
    .description('Show current configuration')
    .option('--json', 'Output as JSON', false)
    .option('--path', 'Show configuration file path', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        const config = await configManager.getConfig();

        if (options.path) {
          console.log(configManager.getConfigPath());
          return;
        }

        if (options.json) {
          // Hide sensitive information
          const publicConfig = {
            apiUrl: config.apiUrl,
            hasApiKey: !!config.apiKey,
            defaultProject: config.defaultProject,
            scanDefaults: config.scanDefaults,
            userPreferences: config.userPreferences
          };
          console.log(JSON.stringify(publicConfig, null, 2));
          return;
        }

        displayConfiguration(config, configManager, logger);

      } catch (error) {
        logger.error('Failed to show configuration:', error);
        process.exit(1);
      }
    });
}

/**
 * Set configuration command
 */
function createSetCommand(): Command {
  return new Command('set')
    .description('Set configuration values')
    .argument('<key>', 'Configuration key (dot notation supported)')
    .argument('<value>', 'Configuration value')
    .option('--type <type>', 'Value type (string, number, boolean, array)', 'string')
    .action(async (key: string, value: string, options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        const config = await configManager.getConfig();

        // Parse value based on type
        let parsedValue: any = value;
        
        switch (options.type) {
          case 'number':
            parsedValue = parseFloat(value);
            if (isNaN(parsedValue)) {
              throw new Error('Invalid number value');
            }
            break;
          case 'boolean':
            parsedValue = value.toLowerCase() === 'true';
            break;
          case 'array':
            parsedValue = value.split(',').map(v => v.trim());
            break;
        }

        // Set configuration value using dot notation
        const updatedConfig = setConfigValue(config, key, parsedValue);
        
        // Validate the configuration
        ConfigManager.validateConfig(updatedConfig);
        
        // Save configuration
        await configManager.updateConfig(updatedConfig);

        logger.success(`✅ Configuration updated: ${chalk.cyan(key)} = ${chalk.yellow(JSON.stringify(parsedValue))}`);

      } catch (error) {
        logger.error('Failed to set configuration:', error);
        process.exit(1);
      }
    });
}

/**
 * Scan defaults command
 */
function createDefaultsCommand(): Command {
  const command = new Command('defaults')
    .description('Manage scan defaults');

  command
    .command('set')
    .description('Set scan defaults')
    .option('-s, --scanners <scanners...>', 'Default scanners')
    .option('--severity <levels...>', 'Default severity levels')
    .option('-f, --format <format>', 'Default output format')
    .option('-t, --timeout <seconds>', 'Default timeout in seconds')
    .option('--interactive', 'Interactive configuration', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        let scanDefaults: any;

        if (options.interactive) {
          scanDefaults = await interactiveScanDefaults(logger);
        } else {
          const current = await configManager.getConfig();
          scanDefaults = { ...current.scanDefaults };

          if (options.scanners) scanDefaults.scanners = options.scanners;
          if (options.severity) scanDefaults.severity = options.severity;
          if (options.format) scanDefaults.format = options.format;
          if (options.timeout) scanDefaults.timeout = parseInt(options.timeout, 10);
        }

        // Validate scan defaults
        ScannerConfigSchema.parse(scanDefaults);

        await configManager.updateScanDefaults(scanDefaults);
        logger.success('✅ Scan defaults updated');

        // Show updated defaults
        logger.info('\n📋 Updated Scan Defaults:');
        displayScanDefaults(scanDefaults, logger);

      } catch (error) {
        logger.error('Failed to set scan defaults:', error);
        process.exit(1);
      }
    });

  command
    .command('show')
    .description('Show current scan defaults')
    .option('--json', 'Output as JSON', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        const config = await configManager.getConfig();

        if (options.json) {
          console.log(JSON.stringify(config.scanDefaults, null, 2));
          return;
        }

        logger.info('\n📋 Current Scan Defaults:');
        displayScanDefaults(config.scanDefaults, logger);

      } catch (error) {
        logger.error('Failed to show scan defaults:', error);
        process.exit(1);
      }
    });

  command
    .command('reset')
    .description('Reset scan defaults')
    .option('-f, --force', 'Force reset without confirmation', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        if (!options.force) {
          const { confirm } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'confirm',
              message: 'Reset scan defaults to factory settings?',
              default: false
            }
          ]);

          if (!confirm) {
            logger.info('Operation cancelled');
            return;
          }
        }

        const configManager = new ConfigManager();
        const defaultConfig = ConfigManager.getDefaultConfig();
        await configManager.updateScanDefaults(defaultConfig.scanDefaults);

        logger.success('✅ Scan defaults reset to factory settings');

      } catch (error) {
        logger.error('Failed to reset scan defaults:', error);
        process.exit(1);
      }
    });

  return command;
}

/**
 * User preferences command
 */
function createPreferencesCommand(): Command {
  const command = new Command('preferences')
    .alias('prefs')
    .description('Manage user preferences');

  command
    .command('set')
    .description('Set user preferences')
    .option('--color <enabled>', 'Enable color output (true/false)')
    .option('--verbose <enabled>', 'Enable verbose logging (true/false)')
    .option('--auto-update <enabled>', 'Enable auto updates (true/false)')
    .option('--interactive', 'Interactive configuration', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        let preferences: any;

        if (options.interactive) {
          preferences = await interactivePreferences(logger);
        } else {
          const current = await configManager.getConfig();
          preferences = { ...current.userPreferences };

          if (options.color !== undefined) {
            preferences.colorOutput = options.color === 'true';
          }
          if (options.verbose !== undefined) {
            preferences.verboseLogging = options.verbose === 'true';
          }
          if (options.autoUpdate !== undefined) {
            preferences.autoUpdate = options.autoUpdate === 'true';
          }
        }

        // Validate preferences
        PreferencesConfigSchema.parse(preferences);

        await configManager.updatePreferences(preferences);
        logger.success('✅ User preferences updated');

        // Show updated preferences
        logger.info('\n👤 Updated Preferences:');
        displayUserPreferences(preferences, logger);

      } catch (error) {
        logger.error('Failed to set preferences:', error);
        process.exit(1);
      }
    });

  command
    .command('show')
    .description('Show current user preferences')
    .option('--json', 'Output as JSON', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        const config = await configManager.getConfig();

        if (options.json) {
          console.log(JSON.stringify(config.userPreferences, null, 2));
          return;
        }

        logger.info('\n👤 Current User Preferences:');
        displayUserPreferences(config.userPreferences, logger);

      } catch (error) {
        logger.error('Failed to show preferences:', error);
        process.exit(1);
      }
    });

  return command;
}

/**
 * Import configuration command
 */
function createImportCommand(): Command {
  return new Command('import')
    .description('Import configuration from file')
    .argument('<file>', 'Configuration file path')
    .option('--merge', 'Merge with existing configuration', false)
    .option('-f, --force', 'Force import without validation', false)
    .action(async (filePath: string, options: any) => {
      const logger = new Logger();

      try {
        // Check if file exists
        const resolvedPath = path.resolve(filePath);
        await fs.access(resolvedPath);

        const configManager = new ConfigManager();

        if (options.merge) {
          // Merge with existing configuration
          const existingConfig = await configManager.getConfig();
          const importedConfigData = await fs.readFile(resolvedPath, 'utf-8');
          const importedConfig = JSON.parse(importedConfigData);
          
          const mergedConfig = ConfigManager.mergeConfigs(existingConfig, importedConfig);
          
          if (!options.force) {
            ConfigManager.validateConfig(mergedConfig);
          }
          
          await configManager.updateConfig(mergedConfig);
          logger.success(`✅ Configuration merged from: ${chalk.cyan(resolvedPath)}`);
        } else {
          // Replace existing configuration
          await configManager.importConfig(resolvedPath);
          logger.success(`✅ Configuration imported from: ${chalk.cyan(resolvedPath)}`);
        }

      } catch (error) {
        logger.error('Failed to import configuration:', error);
        process.exit(1);
      }
    });
}

/**
 * Export configuration command
 */
function createExportCommand(): Command {
  return new Command('export')
    .description('Export configuration to file')
    .argument('<file>', 'Output file path')
    .option('--no-secrets', 'Exclude sensitive information', false)
    .action(async (filePath: string, options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        const config = await configManager.getConfig();

        let exportConfig = { ...config };

        if (options.noSecrets) {
          // Remove sensitive information
          delete exportConfig.apiKey;
        }

        const resolvedPath = path.resolve(filePath);
        await fs.writeFile(resolvedPath, JSON.stringify(exportConfig, null, 2));

        logger.success(`✅ Configuration exported to: ${chalk.cyan(resolvedPath)}`);

      } catch (error) {
        logger.error('Failed to export configuration:', error);
        process.exit(1);
      }
    });
}

/**
 * Reset configuration command
 */
function createResetCommand(): Command {
  return new Command('reset')
    .description('Reset configuration to defaults')
    .option('-f, --force', 'Force reset without confirmation', false)
    .option('--keep-auth', 'Keep authentication settings', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        if (!options.force) {
          logger.warn('⚠️  This will reset all configuration to factory defaults');
          
          const { confirm } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'confirm',
              message: 'Are you sure you want to reset the configuration?',
              default: false
            }
          ]);

          if (!confirm) {
            logger.info('Operation cancelled');
            return;
          }
        }

        const configManager = new ConfigManager();

        if (options.keepAuth) {
          const currentConfig = await configManager.getConfig();
          const defaultConfig = ConfigManager.getDefaultConfig();
          
          // Keep authentication settings
          defaultConfig.apiUrl = currentConfig.apiUrl;
          defaultConfig.apiKey = currentConfig.apiKey;
          defaultConfig.defaultProject = currentConfig.defaultProject;
          
          await configManager.updateConfig(defaultConfig);
        } else {
          await configManager.resetConfig();
        }

        logger.success('✅ Configuration reset to defaults');

      } catch (error) {
        logger.error('Failed to reset configuration:', error);
        process.exit(1);
      }
    });
}

/**
 * Configuration wizard command
 */
function createWizardCommand(): Command {
  return new Command('wizard')
    .description('Interactive configuration wizard')
    .action(async () => {
      const logger = new Logger();

      try {
        await configurationWizard(logger);
      } catch (error) {
        logger.error('Configuration wizard failed:', error);
        process.exit(1);
      }
    });
}

/**
 * Interactive configuration wizard
 */
async function configurationWizard(logger: Logger): Promise<void> {
  logger.info('🧙 Welcome to the SecureScan Configuration Wizard!\n');

  const configManager = new ConfigManager();
  const currentConfig = await configManager.getConfig();

  // API Configuration
  logger.info('📡 API Configuration:');
  const { apiUrl } = await inquirer.prompt([
    {
      type: 'input',
      name: 'apiUrl',
      message: 'API Endpoint URL:',
      default: currentConfig.apiUrl || 'https://api.securescan.io',
      validate: (input: string) => {
        try {
          new URL(input);
          return true;
        } catch {
          return 'Please enter a valid URL';
        }
      }
    }
  ]);

  // Scan Defaults
  logger.info('\n🔍 Scan Defaults:');
  const scanDefaults = await interactiveScanDefaults(logger);

  // User Preferences
  logger.info('\n👤 User Preferences:');
  const userPreferences = await interactivePreferences(logger);

  // Summary and confirmation
  logger.info('\n📋 Configuration Summary:');
  logger.info(`API Endpoint: ${chalk.cyan(apiUrl)}`);
  logger.info(`Default Scanners: ${scanDefaults.scanners.join(', ')}`);
  logger.info(`Severity Levels: ${scanDefaults.severity.join(', ')}`);
  logger.info(`Output Format: ${scanDefaults.format}`);
  logger.info(`Timeout: ${scanDefaults.timeout}s`);
  logger.info(`Color Output: ${userPreferences.colorOutput ? '✅' : '❌'}`);
  logger.info(`Verbose Logging: ${userPreferences.verboseLogging ? '✅' : '❌'}`);
  logger.info(`Auto Update: ${userPreferences.autoUpdate ? '✅' : '❌'}`);

  const { confirm } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'confirm',
      message: 'Save this configuration?',
      default: true
    }
  ]);

  if (confirm) {
    await configManager.updateConfig({
      apiUrl,
      scanDefaults,
      userPreferences
    });

    logger.success('\n✅ Configuration saved successfully!');
    logger.info(`Configuration file: ${chalk.dim(configManager.getConfigPath())}`);
  } else {
    logger.info('Configuration not saved');
  }
}

/**
 * Interactive scan defaults configuration
 */
async function interactiveScanDefaults(logger: Logger): Promise<any> {
  return await inquirer.prompt([
    {
      type: 'checkbox',
      name: 'scanners',
      message: 'Default scanners:',
      choices: [
        { name: 'SAST (Static Analysis)', value: 'sast', checked: true },
        { name: 'SCA (Dependencies)', value: 'sca', checked: true },
        { name: 'Secrets Detection', value: 'secrets', checked: true },
        { name: 'DAST (Dynamic Analysis)', value: 'dast' },
        { name: 'IaC (Infrastructure)', value: 'iac' },
        { name: 'Container Scanning', value: 'container' }
      ],
      validate: (input: string[]) => input.length > 0 || 'Please select at least one scanner'
    },
    {
      type: 'checkbox',
      name: 'severity',
      message: 'Default severity levels:',
      choices: [
        { name: 'Critical', value: 'critical', checked: true },
        { name: 'High', value: 'high', checked: true },
        { name: 'Medium', value: 'medium', checked: true },
        { name: 'Low', value: 'low' }
      ],
      validate: (input: string[]) => input.length > 0 || 'Please select at least one severity level'
    },
    {
      type: 'list',
      name: 'format',
      message: 'Default output format:',
      choices: [
        { name: 'JSON', value: 'json' },
        { name: 'SARIF', value: 'sarif' },
        { name: 'HTML', value: 'html' },
        { name: 'CSV', value: 'csv' }
      ],
      default: 'json'
    },
    {
      type: 'number',
      name: 'timeout',
      message: 'Default timeout (seconds):',
      default: 3600,
      validate: (input: number) => {
        if (input < 60) return 'Timeout must be at least 60 seconds';
        if (input > 7200) return 'Timeout cannot exceed 7200 seconds (2 hours)';
        return true;
      }
    }
  ]);
}

/**
 * Interactive user preferences configuration
 */
async function interactivePreferences(logger: Logger): Promise<any> {
  return await inquirer.prompt([
    {
      type: 'confirm',
      name: 'colorOutput',
      message: 'Enable colored output?',
      default: true
    },
    {
      type: 'confirm',
      name: 'verboseLogging',
      message: 'Enable verbose logging?',
      default: false
    },
    {
      type: 'confirm',
      name: 'autoUpdate',
      message: 'Enable automatic updates?',
      default: true
    }
  ]);
}

/**
 * Display full configuration
 */
function displayConfiguration(config: any, configManager: ConfigManager, logger: Logger): void {
  logger.info('\n⚙️  SecureScan CLI Configuration:\n');

  // API Configuration
  logger.info('📡 API Configuration:');
  if (config.apiUrl) {
    logger.info(`  Endpoint: ${chalk.cyan(config.apiUrl)}`);
  } else {
    logger.warn('  Endpoint: Not configured');
  }
  logger.info(`  API Key: ${config.apiKey ? '✅ Configured' : '❌ Not configured'}`);
  
  if (config.defaultProject) {
    logger.info(`  Default Project: ${chalk.cyan(config.defaultProject)}`);
  }

  // Scan Defaults
  logger.info('\n🔍 Scan Defaults:');
  displayScanDefaults(config.scanDefaults, logger);

  // User Preferences
  logger.info('\n👤 User Preferences:');
  displayUserPreferences(config.userPreferences, logger);

  // File Information
  logger.info('\n📁 Configuration File:');
  logger.info(`  Path: ${chalk.dim(configManager.getConfigPath())}`);
}

/**
 * Display scan defaults
 */
function displayScanDefaults(scanDefaults: any, logger: Logger): void {
  logger.info(`  Scanners: ${scanDefaults.scanners.map((s: string) => chalk.yellow(s)).join(', ')}`);
  logger.info(`  Severity: ${scanDefaults.severity.map((s: string) => chalk.yellow(s)).join(', ')}`);
  logger.info(`  Format: ${chalk.yellow(scanDefaults.format)}`);
  logger.info(`  Timeout: ${chalk.yellow(scanDefaults.timeout)}s`);
}

/**
 * Display user preferences
 */
function displayUserPreferences(preferences: any, logger: Logger): void {
  logger.info(`  Color Output: ${preferences.colorOutput ? '✅ Enabled' : '❌ Disabled'}`);
  logger.info(`  Verbose Logging: ${preferences.verboseLogging ? '✅ Enabled' : '❌ Disabled'}`);
  logger.info(`  Auto Update: ${preferences.autoUpdate ? '✅ Enabled' : '❌ Disabled'}`);
}

/**
 * Set configuration value using dot notation
 */
function setConfigValue(config: any, key: string, value: any): any {
  const keys = key.split('.');
  const result = { ...config };
  let current = result;

  for (let i = 0; i < keys.length - 1; i++) {
    const k = keys[i];
    if (!(k in current) || typeof current[k] !== 'object') {
      current[k] = {};
    }
    current = current[k];
  }

  current[keys[keys.length - 1]] = value;
  return result;
}