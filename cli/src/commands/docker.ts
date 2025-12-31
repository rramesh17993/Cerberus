#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { Logger } from '../lib/logger.js';

const execAsync = promisify(exec);

/**
 * Docker Command - Docker integration utilities
 * 
 * Provides Docker management capabilities including:
 * - Starting/stopping scanner containers
 * - Managing scanner images
 * - Container health checks
 * - Volume management
 */

export function createDockerCommand(): Command {
  const command = new Command('docker')
    .description('Docker integration utilities')
    .usage('<subcommand> [options]');

  // Add subcommands
  command.addCommand(createStatusCommand());
  command.addCommand(createPullCommand());
  command.addCommand(createCleanupCommand());
  command.addCommand(createLogsCommand());
  command.addCommand(createImagesCommand());

  return command;
}

/**
 * Docker status command
 */
function createStatusCommand(): Command {
  return new Command('status')
    .description('Check Docker and scanner container status')
    .option('--verbose', 'Show detailed status information')
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const dockerManager = new DockerManager(logger);
        const status = await dockerManager.getStatus(options.verbose);

        logger.info('\n🐳 Docker Status:');
        logger.info(`Docker Engine: ${status.dockerRunning ? '✅ Running' : '❌ Not Running'}`);
        
        if (status.dockerRunning) {
          logger.info(`Docker Version: ${status.dockerVersion}`);
          
          logger.info('\n📦 Scanner Images:');
          for (const image of status.scannerImages) {
            const statusIcon = image.available ? '✅' : '❌';
            logger.info(`  ${statusIcon} ${image.name} (${image.tag})`);
            if (options.verbose && image.size) {
              logger.info(`    Size: ${image.size}`);
              logger.info(`    Created: ${image.created}`);
            }
          }

          if (status.runningContainers.length > 0) {
            logger.info('\n🔄 Running Containers:');
            for (const container of status.runningContainers) {
              logger.info(`  🏃 ${container.name} (${container.image})`);
              if (options.verbose) {
                logger.info(`    Status: ${container.status}`);
                logger.info(`    Ports: ${container.ports}`);
              }
            }
          }
        }

      } catch (error) {
        logger.error('Failed to check Docker status:', error);
        process.exit(1);
      }
    });
}

/**
 * Pull scanner images command
 */
function createPullCommand(): Command {
  return new Command('pull')
    .description('Pull scanner Docker images')
    .option('-i, --image <image>', 'Specific image to pull (default: all)')
    .option('--force', 'Force pull even if image exists')
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const dockerManager = new DockerManager(logger);
        
        if (options.image) {
          await dockerManager.pullImage(options.image, options.force);
        } else {
          await dockerManager.pullAllImages(options.force);
        }

        logger.success('✅ Images pulled successfully');

      } catch (error) {
        logger.error('Failed to pull images:', error);
        process.exit(1);
      }
    });
}

/**
 * Cleanup command
 */
function createCleanupCommand(): Command {
  return new Command('cleanup')
    .description('Clean up Docker resources')
    .option('--containers', 'Remove stopped scanner containers')
    .option('--images', 'Remove unused scanner images')
    .option('--volumes', 'Remove unused volumes')
    .option('--all', 'Clean up everything')
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const dockerManager = new DockerManager(logger);
        
        if (options.all || options.containers) {
          await dockerManager.cleanupContainers();
        }
        
        if (options.all || options.images) {
          await dockerManager.cleanupImages();
        }
        
        if (options.all || options.volumes) {
          await dockerManager.cleanupVolumes();
        }

        logger.success('✅ Cleanup completed');

      } catch (error) {
        logger.error('Failed to cleanup:', error);
        process.exit(1);
      }
    });
}

/**
 * Logs command
 */
function createLogsCommand(): Command {
  return new Command('logs')
    .description('Show container logs')
    .argument('<container>', 'Container name or ID')
    .option('-f, --follow', 'Follow log output')
    .option('-t, --tail <lines>', 'Number of lines to show from end of logs', '100')
    .action(async (container: string, options: any) => {
      const logger = new Logger();

      try {
        const dockerManager = new DockerManager(logger);
        await dockerManager.showLogs(container, {
          follow: options.follow,
          tail: options.tail
        });

      } catch (error) {
        logger.error('Failed to show logs:', error);
        process.exit(1);
      }
    });
}

/**
 * Images command
 */
function createImagesCommand(): Command {
  return new Command('images')
    .description('List scanner images')
    .option('--verbose', 'Show detailed image information')
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        const dockerManager = new DockerManager(logger);
        const images = await dockerManager.listImages(options.verbose);

        logger.info('\n📦 Scanner Images:');
        for (const image of images) {
          logger.info(`  ${image.repository}:${image.tag}`);
          if (options.verbose) {
            logger.info(`    Image ID: ${image.id}`);
            logger.info(`    Size: ${image.size}`);
            logger.info(`    Created: ${image.created}`);
          }
        }

      } catch (error) {
        logger.error('Failed to list images:', error);
        process.exit(1);
      }
    });
}

/**
 * Docker Manager class
 */
class DockerManager {
  private readonly scannerImages = [
    'semgrep/semgrep:latest',
    'aquasec/trivy:latest',
    'owasp/zap2docker-stable:latest',
    'zricethezav/gitleaks:latest',
    'bridgecrew/checkov:latest'
  ];

  constructor(private logger: Logger) {}

  async getStatus(verbose: boolean = false): Promise<any> {
    const status: any = {
      dockerRunning: false,
      dockerVersion: '',
      scannerImages: [],
      runningContainers: []
    };

    try {
      // Check if Docker is running
      const { stdout: versionOutput } = await execAsync('docker version --format "{{.Server.Version}}"');
      status.dockerRunning = true;
      status.dockerVersion = versionOutput.trim();

      // Check scanner images
      for (const imageName of this.scannerImages) {
        try {
          const { stdout } = await execAsync(`docker images ${imageName} --format "{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"`);
          const available = stdout.trim().length > 0;
          
          if (available) {
            const [imageTag, size, created] = stdout.trim().split('\t');
            status.scannerImages.push({
              name: imageName,
              tag: imageTag.split(':')[1] || 'latest',
              available: true,
              size: verbose ? size : undefined,
              created: verbose ? created : undefined
            });
          } else {
            status.scannerImages.push({
              name: imageName,
              tag: 'latest',
              available: false
            });
          }
        } catch {
          status.scannerImages.push({
            name: imageName,
            tag: 'latest',
            available: false
          });
        }
      }

      // Check running containers
      try {
        const { stdout } = await execAsync('docker ps --format "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"');
        if (stdout.trim()) {
          const containers = stdout.trim().split('\n').map(line => {
            const [name, image, status, ports] = line.split('\t');
            return { name, image, status, ports };
          });
          
          // Filter for scanner-related containers
          status.runningContainers = containers.filter(container =>
            this.scannerImages.some(image => container.image.includes(image.split(':')[0]))
          );
        }
      } catch {
        // No running containers or error
      }

    } catch (error) {
      status.dockerRunning = false;
    }

    return status;
  }

  async pullImage(imageName: string, force: boolean = false): Promise<void> {
    if (!force) {
      // Check if image already exists
      try {
        await execAsync(`docker images ${imageName} --format "{{.Repository}}:{{.Tag}}"`);
        this.logger.info(`Image ${imageName} already exists, use --force to pull anyway`);
        return;
      } catch {
        // Image doesn't exist, proceed with pull
      }
    }

    this.logger.info(`Pulling image: ${chalk.cyan(imageName)}`);
    
    return new Promise((resolve, reject) => {
      const process = spawn('docker', ['pull', imageName], {
        stdio: ['inherit', 'pipe', 'pipe']
      });

      process.stdout?.on('data', (data) => {
        this.logger.info(data.toString().trim());
      });

      process.stderr?.on('data', (data) => {
        this.logger.warn(data.toString().trim());
      });

      process.on('close', (code) => {
        if (code === 0) {
          this.logger.success(`✅ Pulled: ${imageName}`);
          resolve();
        } else {
          reject(new Error(`Failed to pull ${imageName}`));
        }
      });
    });
  }

  async pullAllImages(force: boolean = false): Promise<void> {
    this.logger.info('Pulling all scanner images...');
    
    for (const image of this.scannerImages) {
      try {
        await this.pullImage(image, force);
      } catch (error) {
        this.logger.error(`Failed to pull ${image}:`, error);
      }
    }
  }

  async cleanupContainers(): Promise<void> {
    this.logger.info('Cleaning up stopped containers...');
    
    try {
      const { stdout } = await execAsync('docker ps -a --filter "status=exited" --format "{{.Names}}"');
      const stoppedContainers = stdout.trim().split('\n').filter(name => name);
      
      if (stoppedContainers.length > 0) {
        await execAsync(`docker rm ${stoppedContainers.join(' ')}`);
        this.logger.info(`Removed ${stoppedContainers.length} stopped containers`);
      } else {
        this.logger.info('No stopped containers to remove');
      }
    } catch (error) {
      this.logger.warn('Failed to cleanup containers:', error);
    }
  }

  async cleanupImages(): Promise<void> {
    this.logger.info('Cleaning up unused images...');
    
    try {
      await execAsync('docker image prune -f');
      this.logger.info('Removed unused images');
    } catch (error) {
      this.logger.warn('Failed to cleanup images:', error);
    }
  }

  async cleanupVolumes(): Promise<void> {
    this.logger.info('Cleaning up unused volumes...');
    
    try {
      await execAsync('docker volume prune -f');
      this.logger.info('Removed unused volumes');
    } catch (error) {
      this.logger.warn('Failed to cleanup volumes:', error);
    }
  }

  async showLogs(container: string, options: any): Promise<void> {
    const args = ['logs'];
    
    if (options.follow) {
      args.push('-f');
    }
    
    if (options.tail) {
      args.push('--tail', options.tail);
    }
    
    args.push(container);

    const process = spawn('docker', args, {
      stdio: 'inherit'
    });

    process.on('close', (code) => {
      if (code !== 0) {
        this.logger.error(`Failed to show logs for ${container}`);
      }
    });
  }

  async listImages(verbose: boolean = false): Promise<any[]> {
    const images: any[] = [];
    
    for (const imageName of this.scannerImages) {
      try {
        const format = verbose 
          ? '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedAt}}'
          : '{{.Repository}}\t{{.Tag}}';
          
        const { stdout } = await execAsync(`docker images ${imageName} --format "${format}"`);
        
        if (stdout.trim()) {
          const lines = stdout.trim().split('\n');
          for (const line of lines) {
            if (verbose) {
              const [repository, tag, id, size, created] = line.split('\t');
              images.push({ repository, tag, id, size, created });
            } else {
              const [repository, tag] = line.split('\t');
              images.push({ repository, tag });
            }
          }
        }
      } catch {
        // Image not found, skip
      }
    }
    
    return images;
  }
}