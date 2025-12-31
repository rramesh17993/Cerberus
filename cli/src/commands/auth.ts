#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import ora from 'ora';
import { z } from 'zod';
import { APIClient } from '../lib/api-client.js';
import { ConfigManager } from '../lib/config-manager.js';
import { Logger } from '../lib/logger.js';

/**
 * Authentication Command - Manage authentication with SecureScan Platform
 * 
 * Provides comprehensive authentication capabilities including:
 * - Login with email/password
 * - Login with API key
 * - Logout
 * - Check authentication status
 * - Manage API keys
 * - Configure API endpoint
 */

// Validation schemas
const LoginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required')
});

const APIKeySchema = z.object({
  apiKey: z.string().min(1, 'API key is required')
});

const EndpointSchema = z.object({
  apiUrl: z.string().url('Invalid API URL')
});

export function createAuthCommand(): Command {
  const command = new Command('auth')
    .description('Manage authentication with SecureScan Platform')
    .usage('<subcommand> [options]');

  // Add subcommands
  command.addCommand(createLoginCommand());
  command.addCommand(createLogoutCommand());
  command.addCommand(createStatusCommand());
  command.addCommand(createConfigCommand());
  command.addCommand(createKeyCommand());
  command.addCommand(createWhoamiCommand());

  return command;
}

/**
 * Login command
 */
function createLoginCommand(): Command {
  return new Command('login')
    .description('Login to SecureScan Platform')
    .option('-e, --email <email>', 'Email address')
    .option('-p, --password <password>', 'Password')
    .option('-k, --api-key <key>', 'API key for authentication')
    .option('-u, --api-url <url>', 'API endpoint URL')
    .option('--interactive', 'Interactive login', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        
        // Set API URL if provided
        if (options.apiUrl) {
          const urlValidation = EndpointSchema.safeParse({ apiUrl: options.apiUrl });
          if (!urlValidation.success) {
            logger.error('Invalid API URL:', urlValidation.error.issues[0].message);
            process.exit(1);
          }
          await configManager.updateConfig({ apiUrl: options.apiUrl });
          logger.info(`API endpoint set to: ${chalk.cyan(options.apiUrl)}`);
        }

        const apiClient = new APIClient();

        if (options.apiKey) {
          // Login with API key
          await loginWithAPIKey(options.apiKey, apiClient, configManager, logger);
        } else if (options.email && options.password) {
          // Login with email/password
          await loginWithCredentials(options.email, options.password, apiClient, logger);
        } else {
          // Interactive login
          await interactiveLogin(apiClient, configManager, logger);
        }

      } catch (error) {
        logger.error('Login failed:', error);
        process.exit(1);
      }
    });
}

/**
 * Logout command
 */
function createLogoutCommand(): Command {
  return new Command('logout')
    .description('Logout from SecureScan Platform')
    .option('--keep-config', 'Keep API endpoint configuration', false)
    .action(async (options: any) => {
      const logger = new Logger();
      const spinner = ora('Logging out...').start();

      try {
        const apiClient = new APIClient();
        
        // Attempt to logout from server
        try {
          await apiClient.auth.logout();
        } catch {
          // Server logout may fail, but continue with local cleanup
        }

        // Clear local authentication
        const configManager = new ConfigManager();
        if (options.keepConfig) {
          await configManager.updateConfig({ apiKey: undefined });
        } else {
          await configManager.resetConfig();
        }

        spinner.succeed('Logged out successfully!');
        logger.success('✅ You have been logged out from SecureScan Platform');

      } catch (error) {
        spinner.fail('Logout failed');
        logger.error('Error:', error);
        process.exit(1);
      }
    });
}

/**
 * Authentication status command
 */
function createStatusCommand(): Command {
  return new Command('status')
    .description('Check authentication status')
    .option('--json', 'Output as JSON', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        const config = await configManager.getConfig();
        const apiClient = new APIClient();

        const status = {
          authenticated: false,
          apiUrl: config.apiUrl,
          hasApiKey: !!config.apiKey,
          user: null as any
        };

        if (config.apiKey && config.apiUrl) {
          try {
            const user = await apiClient.auth.getCurrentUser();
            status.authenticated = true;
            status.user = user;
          } catch {
            status.authenticated = false;
          }
        }

        if (options.json) {
          console.log(JSON.stringify(status, null, 2));
          return;
        }

        logger.info('\n🔐 Authentication Status:');
        logger.info(`Status: ${status.authenticated ? chalk.green('✅ Authenticated') : chalk.red('❌ Not authenticated')}`);
        
        if (config.apiUrl) {
          logger.info(`API Endpoint: ${chalk.cyan(config.apiUrl)}`);
        } else {
          logger.warn('⚠️  No API endpoint configured');
        }

        if (status.authenticated && status.user) {
          logger.info(`User: ${chalk.bold(status.user.email)}`);
          logger.info(`Role: ${status.user.role}`);
          if (status.user.organization) {
            logger.info(`Organization: ${status.user.organization.name}`);
          }
        } else {
          logger.warn('⚠️  Not logged in');
          logger.info(`\nUse ${chalk.cyan('securescan auth login')} to authenticate`);
        }

      } catch (error) {
        logger.error('Failed to check authentication status:', error);
        process.exit(1);
      }
    });
}

/**
 * Configuration command
 */
function createConfigCommand(): Command {
  const command = new Command('config')
    .description('Manage authentication configuration');

  command
    .command('set-endpoint')
    .description('Set API endpoint URL')
    .argument('<url>', 'API endpoint URL')
    .action(async (url: string) => {
      const logger = new Logger();

      try {
        const validation = EndpointSchema.safeParse({ apiUrl: url });
        if (!validation.success) {
          logger.error('Invalid URL:', validation.error.issues[0].message);
          process.exit(1);
        }

        const configManager = new ConfigManager();
        await configManager.updateConfig({ apiUrl: url });

        logger.success(`✅ API endpoint set to: ${chalk.cyan(url)}`);

      } catch (error) {
        logger.error('Failed to set endpoint:', error);
        process.exit(1);
      }
    });

  command
    .command('show')
    .description('Show current configuration')
    .option('--json', 'Output as JSON', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const configManager = new ConfigManager();
        const config = await configManager.getConfig();

        if (options.json) {
          // Hide sensitive information in JSON output
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

        logger.info('\n⚙️  Configuration:');
        
        if (config.apiUrl) {
          logger.info(`API Endpoint: ${chalk.cyan(config.apiUrl)}`);
        } else {
          logger.warn('API Endpoint: Not configured');
        }

        logger.info(`API Key: ${config.apiKey ? '✅ Configured' : '❌ Not configured'}`);
        
        if (config.defaultProject) {
          logger.info(`Default Project: ${chalk.cyan(config.defaultProject)}`);
        }

        logger.info('\nScan Defaults:');
        logger.info(`  Scanners: ${config.scanDefaults.scanners.join(', ')}`);
        logger.info(`  Severity: ${config.scanDefaults.severity.join(', ')}`);
        logger.info(`  Format: ${config.scanDefaults.format}`);
        logger.info(`  Timeout: ${config.scanDefaults.timeout}s`);

        logger.info('\nUser Preferences:');
        logger.info(`  Color Output: ${config.userPreferences.colorOutput ? '✅' : '❌'}`);
        logger.info(`  Verbose Logging: ${config.userPreferences.verboseLogging ? '✅' : '❌'}`);
        logger.info(`  Auto Update: ${config.userPreferences.autoUpdate ? '✅' : '❌'}`);

        logger.info(`\nConfig File: ${chalk.dim(configManager.getConfigPath())}`);

      } catch (error) {
        logger.error('Failed to show configuration:', error);
        process.exit(1);
      }
    });

  command
    .command('reset')
    .description('Reset configuration to defaults')
    .option('-f, --force', 'Force reset without confirmation', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        if (!options.force) {
          const { confirm } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'confirm',
              message: 'Are you sure you want to reset all configuration?',
              default: false
            }
          ]);

          if (!confirm) {
            logger.info('Operation cancelled');
            return;
          }
        }

        const configManager = new ConfigManager();
        await configManager.resetConfig();

        logger.success('✅ Configuration reset to defaults');

      } catch (error) {
        logger.error('Failed to reset configuration:', error);
        process.exit(1);
      }
    });

  return command;
}

/**
 * API Key management command
 */
function createKeyCommand(): Command {
  const command = new Command('key')
    .description('Manage API keys');

  command
    .command('set')
    .description('Set API key')
    .argument('<api-key>', 'API key')
    .action(async (apiKey: string) => {
      const logger = new Logger();

      try {
        const validation = APIKeySchema.safeParse({ apiKey });
        if (!validation.success) {
          logger.error('Invalid API key:', validation.error.issues[0].message);
          process.exit(1);
        }

        const apiClient = new APIClient();
        await loginWithAPIKey(apiKey, apiClient, new ConfigManager(), logger);

      } catch (error) {
        logger.error('Failed to set API key:', error);
        process.exit(1);
      }
    });

  command
    .command('generate')
    .description('Generate a new API key')
    .option('-n, --name <name>', 'API key name/description')
    .option('--expires <days>', 'Expiration in days', '90')
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const apiClient = new APIClient();
        
        // Check if user is authenticated
        try {
          await apiClient.auth.getCurrentUser();
        } catch {
          logger.error('You must be logged in to generate API keys');
          logger.info(`Use ${chalk.cyan('securescan auth login')} first`);
          process.exit(1);
        }

        const keyData = {
          name: options.name || `CLI Key - ${new Date().toISOString()}`,
          expiresInDays: parseInt(options.expires, 10)
        };

        const spinner = ora('Generating API key...').start();
        const response = await apiClient.post('/auth/api-keys', keyData);
        const newKey = response.data;

        spinner.succeed('API key generated successfully!');

        logger.success('✅ New API key created:');
        logger.info(`Name: ${chalk.cyan(newKey.name)}`);
        logger.info(`Key: ${chalk.yellow(newKey.key)}`);
        logger.info(`Expires: ${new Date(newKey.expiresAt).toLocaleString()}`);
        
        logger.warn('\n⚠️  Save this key securely - it will not be shown again!');

        const { useAsDefault } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'useAsDefault',
            message: 'Use this key as your default API key?',
            default: true
          }
        ]);

        if (useAsDefault) {
          const configManager = new ConfigManager();
          await configManager.updateConfig({ apiKey: newKey.key });
          logger.success('✅ API key set as default');
        }

      } catch (error) {
        logger.error('Failed to generate API key:', error);
        process.exit(1);
      }
    });

  command
    .command('list')
    .description('List API keys')
    .option('--json', 'Output as JSON', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const apiClient = new APIClient();
        const response = await apiClient.get('/auth/api-keys');
        const keys = response.data;

        if (options.json) {
          console.log(JSON.stringify(keys, null, 2));
          return;
        }

        if (!keys.length) {
          logger.info('📋 No API keys found');
          logger.info(`Use ${chalk.cyan('securescan auth key generate')} to create one`);
          return;
        }

        logger.info('\n🔑 API Keys:');
        
        keys.forEach((key: any) => {
          const isExpired = new Date(key.expiresAt) < new Date();
          const status = isExpired ? chalk.red('Expired') : chalk.green('Active');
          
          logger.info(`\n${chalk.bold(key.name)}`);
          logger.info(`  ID: ${key.id}`);
          logger.info(`  Status: ${status}`);
          logger.info(`  Created: ${new Date(key.createdAt).toLocaleString()}`);
          logger.info(`  Expires: ${new Date(key.expiresAt).toLocaleString()}`);
          logger.info(`  Last Used: ${key.lastUsedAt ? new Date(key.lastUsedAt).toLocaleString() : 'Never'}`);
        });

      } catch (error) {
        logger.error('Failed to list API keys:', error);
        process.exit(1);
      }
    });

  command
    .command('revoke')
    .description('Revoke an API key')
    .argument('<key-id>', 'API key ID')
    .option('-f, --force', 'Force revocation without confirmation', false)
    .action(async (keyId: string, options: any) => {
      const logger = new Logger();

      try {
        const apiClient = new APIClient();
        
        if (!options.force) {
          const { confirm } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'confirm',
              message: `Are you sure you want to revoke API key ${keyId}?`,
              default: false
            }
          ]);

          if (!confirm) {
            logger.info('Operation cancelled');
            return;
          }
        }

        const spinner = ora('Revoking API key...').start();
        await apiClient.delete(`/auth/api-keys/${keyId}`);

        spinner.succeed('API key revoked successfully!');
        logger.success(`✅ API key ${keyId} has been revoked`);

      } catch (error) {
        logger.error('Failed to revoke API key:', error);
        process.exit(1);
      }
    });

  return command;
}

/**
 * Who am I command
 */
function createWhoamiCommand(): Command {
  return new Command('whoami')
    .description('Show current user information')
    .option('--json', 'Output as JSON', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const apiClient = new APIClient();
        const user = await apiClient.auth.getCurrentUser();

        if (options.json) {
          console.log(JSON.stringify(user, null, 2));
          return;
        }

        logger.info('\n👤 Current User:');
        logger.info(`Email: ${chalk.cyan(user.email)}`);
        logger.info(`Name: ${user.firstName} ${user.lastName}`);
        logger.info(`Role: ${chalk.yellow(user.role)}`);
        
        if (user.organization) {
          logger.info(`Organization: ${chalk.bold(user.organization.name)}`);
          logger.info(`Organization Role: ${user.organizationRole}`);
        }
        
        logger.info(`Account Created: ${new Date(user.createdAt).toLocaleString()}`);
        logger.info(`Last Login: ${new Date(user.lastLoginAt).toLocaleString()}`);

        if (user.permissions?.length) {
          logger.info(`\nPermissions: ${user.permissions.join(', ')}`);
        }

      } catch (error) {
        logger.error('Failed to get user information:', error);
        logger.info(`Use ${chalk.cyan('securescan auth login')} to authenticate`);
        process.exit(1);
      }
    });
}

/**
 * Interactive login flow
 */
async function interactiveLogin(
  apiClient: APIClient, 
  configManager: ConfigManager, 
  logger: Logger
): Promise<void> {
  logger.info('🔐 SecureScan Platform Login\n');

  // Check if API endpoint is configured
  const config = await configManager.getConfig();
  if (!config.apiUrl) {
    const { apiUrl } = await inquirer.prompt([
      {
        type: 'input',
        name: 'apiUrl',
        message: 'API Endpoint URL:',
        default: 'https://api.securescan.io',
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

    await configManager.updateConfig({ apiUrl });
    logger.info(`API endpoint set to: ${chalk.cyan(apiUrl)}\n`);
  }

  // Choose authentication method
  const { method } = await inquirer.prompt([
    {
      type: 'list',
      name: 'method',
      message: 'Choose authentication method:',
      choices: [
        { name: '🔑 API Key', value: 'apikey' },
        { name: '📧 Email & Password', value: 'credentials' }
      ]
    }
  ]);

  if (method === 'apikey') {
    const { apiKey } = await inquirer.prompt([
      {
        type: 'password',
        name: 'apiKey',
        message: 'API Key:',
        mask: '*'
      }
    ]);

    await loginWithAPIKey(apiKey, apiClient, configManager, logger);
  } else {
    const { email, password } = await inquirer.prompt([
      {
        type: 'input',
        name: 'email',
        message: 'Email:',
        validate: (input: string) => {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          return emailRegex.test(input) || 'Please enter a valid email address';
        }
      },
      {
        type: 'password',
        name: 'password',
        message: 'Password:',
        mask: '*'
      }
    ]);

    await loginWithCredentials(email, password, apiClient, logger);
  }
}

/**
 * Login with API key
 */
async function loginWithAPIKey(
  apiKey: string, 
  apiClient: APIClient, 
  configManager: ConfigManager, 
  logger: Logger
): Promise<void> {
  const spinner = ora('Authenticating with API key...').start();

  try {
    await apiClient.auth.loginWithApiKey(apiKey);
    const user = await apiClient.auth.getCurrentUser();

    spinner.succeed('Authentication successful!');
    logger.success(`✅ Logged in as: ${chalk.cyan(user.email)}`);
    
    if (user.organization) {
      logger.info(`Organization: ${chalk.bold(user.organization.name)}`);
    }

  } catch (error) {
    spinner.fail('Authentication failed');
    throw error;
  }
}

/**
 * Login with email and password
 */
async function loginWithCredentials(
  email: string, 
  password: string, 
  apiClient: APIClient, 
  logger: Logger
): Promise<void> {
  const validation = LoginSchema.safeParse({ email, password });
  if (!validation.success) {
    throw new Error(validation.error.issues[0].message);
  }

  const spinner = ora('Authenticating...').start();

  try {
    const response = await apiClient.auth.login(email, password);
    const user = response.user;

    spinner.succeed('Authentication successful!');
    logger.success(`✅ Logged in as: ${chalk.cyan(user.email)}`);
    
    if (user.organization) {
      logger.info(`Organization: ${chalk.bold(user.organization.name)}`);
    }

    logger.info(`Access token expires: ${new Date(response.expiresAt).toLocaleString()}`);

  } catch (error) {
    spinner.fail('Authentication failed');
    throw error;
  }
}