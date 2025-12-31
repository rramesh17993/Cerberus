import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { z } from 'zod';

/**
 * Configuration Manager for SecureScan CLI
 * 
 * Handles reading and writing configuration files, including:
 * - API endpoint configuration
 * - Authentication tokens
 * - Default scan settings
 * - User preferences
 */

// Configuration schema validation
const ConfigSchema = z.object({
  apiUrl: z.string().url().optional(),
  apiKey: z.string().optional(),
  defaultProject: z.string().optional(),
  scanDefaults: z.object({
    scanners: z.array(z.string()).default(['sast', 'sca', 'secrets']),
    severity: z.array(z.string()).default(['medium', 'high', 'critical']),
    format: z.string().default('json'),
    timeout: z.number().default(3600)
  }).default({}),
  userPreferences: z.object({
    colorOutput: z.boolean().default(true),
    verboseLogging: z.boolean().default(false),
    autoUpdate: z.boolean().default(true)
  }).default({})
});

export type Config = z.infer<typeof ConfigSchema>;

export class ConfigManager {
  private configPath: string;
  private config: Config | null = null;

  constructor() {
    // Determine config file location
    const configDir = process.env.SECURESCAN_CONFIG_DIR || 
                      path.join(os.homedir(), '.securescan');
    this.configPath = path.join(configDir, 'config.json');
  }

  /**
   * Get the current configuration
   */
  async getConfig(): Promise<Config> {
    if (!this.config) {
      await this.loadConfig();
    }
    return this.config!;
  }

  /**
   * Update configuration values
   */
  async updateConfig(updates: Partial<Config>): Promise<void> {
    const currentConfig = await this.getConfig();
    const newConfig = { ...currentConfig, ...updates };
    
    // Validate the configuration
    this.config = ConfigSchema.parse(newConfig);
    
    // Save to file
    await this.saveConfig();
  }

  /**
   * Set API endpoint and authentication
   */
  async setAPI(apiUrl: string, apiKey?: string): Promise<void> {
    await this.updateConfig({ apiUrl, apiKey });
  }

  /**
   * Set default project
   */
  async setDefaultProject(projectId: string): Promise<void> {
    await this.updateConfig({ defaultProject: projectId });
  }

  /**
   * Update scan defaults
   */
  async updateScanDefaults(defaults: Partial<Config['scanDefaults']>): Promise<void> {
    const currentConfig = await this.getConfig();
    const newScanDefaults = { ...currentConfig.scanDefaults, ...defaults };
    await this.updateConfig({ scanDefaults: newScanDefaults });
  }

  /**
   * Update user preferences
   */
  async updatePreferences(preferences: Partial<Config['userPreferences']>): Promise<void> {
    const currentConfig = await this.getConfig();
    const newPreferences = { ...currentConfig.userPreferences, ...preferences };
    await this.updateConfig({ userPreferences: newPreferences });
  }

  /**
   * Get API configuration
   */
  async getAPIConfig(): Promise<{ apiUrl?: string; apiKey?: string }> {
    const config = await this.getConfig();
    return {
      apiUrl: config.apiUrl,
      apiKey: config.apiKey
    };
  }

  /**
   * Check if API is configured
   */
  async isAPIConfigured(): Promise<boolean> {
    const { apiUrl, apiKey } = await this.getAPIConfig();
    return !!(apiUrl && apiKey);
  }

  /**
   * Reset configuration to defaults
   */
  async resetConfig(): Promise<void> {
    this.config = ConfigSchema.parse({});
    await this.saveConfig();
  }

  /**
   * Get configuration file path
   */
  getConfigPath(): string {
    return this.configPath;
  }

  /**
   * Load configuration from file
   */
  private async loadConfig(): Promise<void> {
    try {
      // Ensure config directory exists
      await fs.mkdir(path.dirname(this.configPath), { recursive: true });
      
      // Try to read existing config
      const configData = await fs.readFile(this.configPath, 'utf-8');
      const rawConfig = JSON.parse(configData);
      
      // Validate and parse configuration
      this.config = ConfigSchema.parse(rawConfig);
      
    } catch (error) {
      // If file doesn't exist or is invalid, create default config
      this.config = ConfigSchema.parse({});
      await this.saveConfig();
    }
  }

  /**
   * Save configuration to file
   */
  private async saveConfig(): Promise<void> {
    try {
      // Ensure config directory exists
      await fs.mkdir(path.dirname(this.configPath), { recursive: true });
      
      // Write configuration to file
      const configData = JSON.stringify(this.config, null, 2);
      await fs.writeFile(this.configPath, configData, 'utf-8');
      
    } catch (error) {
      throw new Error(`Failed to save configuration: ${error}`);
    }
  }

  /**
   * Import configuration from file
   */
  async importConfig(filePath: string): Promise<void> {
    try {
      const configData = await fs.readFile(filePath, 'utf-8');
      const rawConfig = JSON.parse(configData);
      
      // Validate and update configuration
      this.config = ConfigSchema.parse(rawConfig);
      await this.saveConfig();
      
    } catch (error) {
      throw new Error(`Failed to import configuration: ${error}`);
    }
  }

  /**
   * Export configuration to file
   */
  async exportConfig(filePath: string): Promise<void> {
    try {
      const config = await this.getConfig();
      const configData = JSON.stringify(config, null, 2);
      await fs.writeFile(filePath, configData, 'utf-8');
      
    } catch (error) {
      throw new Error(`Failed to export configuration: ${error}`);
    }
  }

  /**
   * Validate configuration format
   */
  static validateConfig(config: any): Config {
    return ConfigSchema.parse(config);
  }

  /**
   * Get default configuration
   */
  static getDefaultConfig(): Config {
    return ConfigSchema.parse({});
  }

  /**
   * Merge configurations
   */
  static mergeConfigs(base: Config, overrides: Partial<Config>): Config {
    return ConfigSchema.parse({
      ...base,
      ...overrides,
      scanDefaults: {
        ...base.scanDefaults,
        ...(overrides.scanDefaults || {})
      },
      userPreferences: {
        ...base.userPreferences,
        ...(overrides.userPreferences || {})
      }
    });
  }
}