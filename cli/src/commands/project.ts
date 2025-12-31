#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import ora from 'ora';
import Table from 'cli-table3';
import { z } from 'zod';
import { APIClient } from '../lib/api-client.js';
import { ConfigManager } from '../lib/config-manager.js';
import { Logger } from '../lib/logger.js';

/**
 * Project Command - Manage projects in SecureScan Platform
 * 
 * Provides comprehensive project management capabilities including:
 * - Creating new projects
 * - Listing existing projects
 * - Updating project settings
 * - Deleting projects
 * - Setting default project for scans
 */

// Validation schemas
const ProjectCreateSchema = z.object({
  name: z.string().min(1, 'Project name is required'),
  description: z.string().optional(),
  repositoryUrl: z.string().url().optional(),
  visibility: z.enum(['public', 'private']).default('private'),
  tags: z.array(z.string()).default([]),
  settings: z.object({
    autoScan: z.boolean().default(false),
    scanTriggers: z.array(z.enum(['push', 'pr', 'schedule'])).default([]),
    defaultScanners: z.array(z.string()).default(['sast', 'sca', 'secrets']),
    notifications: z.object({
      email: z.boolean().default(true),
      slack: z.boolean().default(false),
      webhook: z.string().url().optional()
    }).default({})
  }).default({})
});

const ProjectUpdateSchema = ProjectCreateSchema.partial();

type ProjectCreateData = z.infer<typeof ProjectCreateSchema>;
type ProjectUpdateData = z.infer<typeof ProjectUpdateSchema>;

interface Project {
  id: string;
  name: string;
  description?: string;
  repositoryUrl?: string;
  visibility: 'public' | 'private';
  tags: string[];
  settings: any;
  stats?: {
    totalScans: number;
    lastScanDate?: string;
    vulnerabilityCount: number;
  };
  createdAt: string;
  updatedAt: string;
}

export function createProjectCommand(): Command {
  const command = new Command('project')
    .alias('projects')
    .description('Manage SecureScan projects')
    .usage('<subcommand> [options]');

  // Add subcommands
  command.addCommand(createListCommand());
  command.addCommand(createShowCommand());
  command.addCommand(createCreateCommand());
  command.addCommand(createUpdateCommand());
  command.addCommand(createDeleteCommand());
  command.addCommand(createSetDefaultCommand());
  command.addCommand(createStatsCommand());

  return command;
}

/**
 * List projects command
 */
function createListCommand(): Command {
  return new Command('list')
    .alias('ls')
    .description('List all projects')
    .option('-s, --search <query>', 'Search projects by name or description')
    .option('-t, --tag <tags...>', 'Filter by tags')
    .option('-v, --visibility <type>', 'Filter by visibility (public/private)')
    .option('-l, --limit <number>', 'Number of projects to show', '20')
    .option('--page <number>', 'Page number', '1')
    .option('--json', 'Output as JSON', false)
    .option('--sort <field>', 'Sort by field (name, created, updated)', 'name')
    .action(async (options: any) => {
      const logger = new Logger();
      const spinner = ora('Fetching projects...').start();

      try {
        const apiClient = new APIClient();
        
        // Build query parameters
        const params: any = {
          page: parseInt(options.page, 10),
          pageSize: parseInt(options.limit, 10),
          sort: options.sort
        };

        if (options.search) params.search = options.search;
        if (options.tag) params.tags = options.tag;
        if (options.visibility) params.visibility = options.visibility;

        const response = await apiClient.projects.list(params);
        const { data: projects, total, page, pageSize, hasNext } = response;

        spinner.stop();

        if (options.json) {
          console.log(JSON.stringify({ projects, total, page, pageSize, hasNext }, null, 2));
          return;
        }

        if (!projects.length) {
          logger.info('📋 No projects found');
          
          const { createNew } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'createNew',
              message: 'Would you like to create a new project?',
              default: true
            }
          ]);

          if (createNew) {
            await createInteractiveProject(logger);
          }
          return;
        }

        // Display projects table
        displayProjectsTable(projects, logger);

        // Show pagination info
        if (hasNext || page > 1) {
          logger.info(`\n📄 Page ${page} of ${Math.ceil(total / pageSize)} (${total} total projects)`);
          if (hasNext) {
            logger.info(`Use ${chalk.cyan(`--page ${page + 1}`)} to see more projects`);
          }
        }

      } catch (error) {
        spinner.fail('Failed to fetch projects');
        logger.error('Error:', error);
        process.exit(1);
      }
    });
}

/**
 * Show project details command
 */
function createShowCommand(): Command {
  return new Command('show')
    .alias('get')
    .description('Show detailed information about a project')
    .argument('<project-id>', 'Project ID or name')
    .option('--json', 'Output as JSON', false)
    .action(async (projectId: string, options: any) => {
      const logger = new Logger();
      const spinner = ora('Fetching project details...').start();

      try {
        const apiClient = new APIClient();
        const project = await apiClient.projects.get(projectId);

        spinner.stop();

        if (options.json) {
          console.log(JSON.stringify(project, null, 2));
          return;
        }

        displayProjectDetails(project, logger);

      } catch (error) {
        spinner.fail('Failed to fetch project details');
        logger.error('Error:', error);
        process.exit(1);
      }
    });
}

/**
 * Create project command
 */
function createCreateCommand(): Command {
  return new Command('create')
    .alias('new')
    .description('Create a new project')
    .option('-n, --name <name>', 'Project name')
    .option('-d, --description <description>', 'Project description')
    .option('-r, --repository <url>', 'Repository URL')
    .option('--visibility <type>', 'Project visibility (public/private)', 'private')
    .option('-t, --tags <tags...>', 'Project tags')
    .option('--interactive', 'Interactive project creation', false)
    .option('--json', 'Output as JSON', false)
    .action(async (options: any) => {
      const logger = new Logger();

      try {
        let projectData: ProjectCreateData;

        if (options.interactive || !options.name) {
          projectData = await createInteractiveProject(logger);
        } else {
          projectData = ProjectCreateSchema.parse({
            name: options.name,
            description: options.description,
            repositoryUrl: options.repository,
            visibility: options.visibility,
            tags: options.tags || []
          });
        }

        const spinner = ora('Creating project...').start();
        
        const apiClient = new APIClient();
        const project = await apiClient.projects.create(projectData);

        spinner.succeed('Project created successfully!');

        if (options.json) {
          console.log(JSON.stringify(project, null, 2));
        } else {
          logger.success(`✅ Project "${project.name}" created with ID: ${chalk.cyan(project.id)}`);
          
          const { setDefault } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'setDefault',
              message: 'Set this as your default project?',
              default: true
            }
          ]);

          if (setDefault) {
            const configManager = new ConfigManager();
            await configManager.setDefaultProject(project.id);
            logger.success('✅ Default project updated');
          }
        }

      } catch (error) {
        logger.error('Failed to create project:', error);
        process.exit(1);
      }
    });
}

/**
 * Update project command
 */
function createUpdateCommand(): Command {
  return new Command('update')
    .alias('edit')
    .description('Update an existing project')
    .argument('<project-id>', 'Project ID or name')
    .option('-n, --name <name>', 'Project name')
    .option('-d, --description <description>', 'Project description')
    .option('-r, --repository <url>', 'Repository URL')
    .option('--visibility <type>', 'Project visibility (public/private)')
    .option('-t, --tags <tags...>', 'Project tags')
    .option('--interactive', 'Interactive project update', false)
    .option('--json', 'Output as JSON', false)
    .action(async (projectId: string, options: any) => {
      const logger = new Logger();

      try {
        const apiClient = new APIClient();
        
        // Get current project data
        const currentProject = await apiClient.projects.get(projectId);

        let updateData: ProjectUpdateData;

        if (options.interactive) {
          updateData = await updateInteractiveProject(currentProject, logger);
        } else {
          updateData = ProjectUpdateSchema.parse({
            name: options.name,
            description: options.description,
            repositoryUrl: options.repository,
            visibility: options.visibility,
            tags: options.tags
          });

          // Remove undefined values
          Object.keys(updateData).forEach(key => {
            if (updateData[key as keyof ProjectUpdateData] === undefined) {
              delete updateData[key as keyof ProjectUpdateData];
            }
          });
        }

        if (Object.keys(updateData).length === 0) {
          logger.warn('No changes specified');
          return;
        }

        const spinner = ora('Updating project...').start();
        const updatedProject = await apiClient.projects.update(projectId, updateData);

        spinner.succeed('Project updated successfully!');

        if (options.json) {
          console.log(JSON.stringify(updatedProject, null, 2));
        } else {
          logger.success(`✅ Project "${updatedProject.name}" updated`);
          displayProjectDetails(updatedProject, logger);
        }

      } catch (error) {
        logger.error('Failed to update project:', error);
        process.exit(1);
      }
    });
}

/**
 * Delete project command
 */
function createDeleteCommand(): Command {
  return new Command('delete')
    .alias('remove')
    .description('Delete a project')
    .argument('<project-id>', 'Project ID or name')
    .option('-f, --force', 'Force deletion without confirmation', false)
    .action(async (projectId: string, options: any) => {
      const logger = new Logger();

      try {
        const apiClient = new APIClient();
        
        // Get project details for confirmation
        const project = await apiClient.projects.get(projectId);

        if (!options.force) {
          logger.warn(`⚠️  You are about to delete project: ${chalk.red(project.name)}`);
          logger.warn('This action cannot be undone and will delete all associated scans and data.');

          const { confirm } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'confirm',
              message: 'Are you sure you want to delete this project?',
              default: false
            }
          ]);

          if (!confirm) {
            logger.info('Operation cancelled');
            return;
          }
        }

        const spinner = ora('Deleting project...').start();
        await apiClient.projects.delete(projectId);

        spinner.succeed('Project deleted successfully!');
        logger.success(`✅ Project "${project.name}" has been deleted`);

      } catch (error) {
        logger.error('Failed to delete project:', error);
        process.exit(1);
      }
    });
}

/**
 * Set default project command
 */
function createSetDefaultCommand(): Command {
  return new Command('set-default')
    .alias('default')
    .description('Set default project for scans')
    .argument('[project-id]', 'Project ID or name (will prompt if not provided)')
    .action(async (projectId?: string) => {
      const logger = new Logger();

      try {
        const apiClient = new APIClient();
        
        let selectedProjectId = projectId;

        if (!selectedProjectId) {
          // Show project selection
          const projects = await apiClient.projects.list({ pageSize: 100 });
          
          if (!projects.data.length) {
            logger.error('No projects found');
            return;
          }

          const { selectedProject } = await inquirer.prompt([
            {
              type: 'list',
              name: 'selectedProject',
              message: 'Select default project:',
              choices: projects.data.map((p: Project) => ({
                name: `${p.name} (${p.id})`,
                value: p.id
              }))
            }
          ]);

          selectedProjectId = selectedProject;
        }

        // Validate project exists
        const project = await apiClient.projects.get(selectedProjectId!);

        // Update config
        const configManager = new ConfigManager();
        await configManager.setDefaultProject(selectedProjectId!);

        logger.success(`✅ Default project set to: ${chalk.cyan(project.name)}`);

      } catch (error) {
        logger.error('Failed to set default project:', error);
        process.exit(1);
      }
    });
}

/**
 * Project statistics command
 */
function createStatsCommand(): Command {
  return new Command('stats')
    .description('Show project statistics')
    .argument('[project-id]', 'Project ID or name (shows all if not provided)')
    .option('--json', 'Output as JSON', false)
    .action(async (projectId?: string, options?: any) => {
      const logger = new Logger();
      const spinner = ora('Fetching project statistics...').start();

      try {
        const apiClient = new APIClient();

        if (projectId) {
          // Show stats for specific project
          const project = await apiClient.projects.get(projectId);
          spinner.stop();

          if (options?.json) {
            console.log(JSON.stringify(project.stats || {}, null, 2));
          } else {
            displayProjectStats(project, logger);
          }
        } else {
          // Show stats for all projects
          const projects = await apiClient.projects.list({ pageSize: 100 });
          spinner.stop();

          if (options?.json) {
            const stats = projects.data.map((p: Project) => ({
              id: p.id,
              name: p.name,
              stats: p.stats || {}
            }));
            console.log(JSON.stringify(stats, null, 2));
          } else {
            displayAllProjectsStats(projects.data, logger);
          }
        }

      } catch (error) {
        spinner.fail('Failed to fetch project statistics');
        logger.error('Error:', error);
        process.exit(1);
      }
    });
}

/**
 * Interactive project creation
 */
async function createInteractiveProject(logger: Logger): Promise<ProjectCreateData> {
  logger.info('🚀 Creating a new project...\n');

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'name',
      message: 'Project name:',
      validate: (input: string) => input.trim().length > 0 || 'Project name is required'
    },
    {
      type: 'input',
      name: 'description',
      message: 'Project description (optional):'
    },
    {
      type: 'input',
      name: 'repositoryUrl',
      message: 'Repository URL (optional):',
      validate: (input: string) => {
        if (!input) return true;
        try {
          new URL(input);
          return true;
        } catch {
          return 'Please enter a valid URL';
        }
      }
    },
    {
      type: 'list',
      name: 'visibility',
      message: 'Project visibility:',
      choices: [
        { name: 'Private', value: 'private' },
        { name: 'Public', value: 'public' }
      ],
      default: 'private'
    },
    {
      type: 'input',
      name: 'tags',
      message: 'Tags (comma-separated):',
      filter: (input: string) => input.split(',').map(tag => tag.trim()).filter(Boolean)
    },
    {
      type: 'checkbox',
      name: 'defaultScanners',
      message: 'Default scanners:',
      choices: [
        { name: 'SAST (Static Analysis)', value: 'sast', checked: true },
        { name: 'SCA (Dependencies)', value: 'sca', checked: true },
        { name: 'Secrets Detection', value: 'secrets', checked: true },
        { name: 'DAST (Dynamic Analysis)', value: 'dast' },
        { name: 'IaC (Infrastructure)', value: 'iac' },
        { name: 'Container Scanning', value: 'container' }
      ]
    },
    {
      type: 'confirm',
      name: 'autoScan',
      message: 'Enable automatic scanning on code changes?',
      default: false
    }
  ]);

  return ProjectCreateSchema.parse({
    ...answers,
    settings: {
      autoScan: answers.autoScan,
      defaultScanners: answers.defaultScanners,
      scanTriggers: answers.autoScan ? ['push'] : [],
      notifications: { email: true }
    }
  });
}

/**
 * Interactive project update
 */
async function updateInteractiveProject(currentProject: Project, logger: Logger): Promise<ProjectUpdateData> {
  logger.info(`🔧 Updating project: ${chalk.cyan(currentProject.name)}\n`);

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'name',
      message: 'Project name:',
      default: currentProject.name
    },
    {
      type: 'input',
      name: 'description',
      message: 'Project description:',
      default: currentProject.description || ''
    },
    {
      type: 'input',
      name: 'repositoryUrl',
      message: 'Repository URL:',
      default: currentProject.repositoryUrl || ''
    },
    {
      type: 'list',
      name: 'visibility',
      message: 'Project visibility:',
      choices: [
        { name: 'Private', value: 'private' },
        { name: 'Public', value: 'public' }
      ],
      default: currentProject.visibility
    },
    {
      type: 'input',
      name: 'tags',
      message: 'Tags (comma-separated):',
      default: currentProject.tags.join(', '),
      filter: (input: string) => input.split(',').map(tag => tag.trim()).filter(Boolean)
    }
  ]);

  return ProjectUpdateSchema.parse(answers);
}

/**
 * Display projects in a table
 */
function displayProjectsTable(projects: Project[], logger: Logger): void {
  const table = new Table({
    head: ['ID', 'Name', 'Visibility', 'Scans', 'Vulnerabilities', 'Last Scan', 'Created'],
    style: { head: ['cyan'] }
  });

  projects.forEach(project => {
    table.push([
      project.id.substring(0, 8) + '...',
      project.name,
      project.visibility === 'private' ? '🔒 Private' : '🌐 Public',
      project.stats?.totalScans || '0',
      project.stats?.vulnerabilityCount || '0',
      project.stats?.lastScanDate 
        ? new Date(project.stats.lastScanDate).toLocaleDateString()
        : 'Never',
      new Date(project.createdAt).toLocaleDateString()
    ]);
  });

  console.log(table.toString());
}

/**
 * Display detailed project information
 */
function displayProjectDetails(project: Project, logger: Logger): void {
  logger.info(`\n📋 Project Details:`);
  logger.info(`ID: ${chalk.cyan(project.id)}`);
  logger.info(`Name: ${chalk.bold(project.name)}`);
  
  if (project.description) {
    logger.info(`Description: ${project.description}`);
  }
  
  if (project.repositoryUrl) {
    logger.info(`Repository: ${chalk.blue(project.repositoryUrl)}`);
  }
  
  logger.info(`Visibility: ${project.visibility === 'private' ? '🔒 Private' : '🌐 Public'}`);
  
  if (project.tags.length) {
    logger.info(`Tags: ${project.tags.map(tag => chalk.yellow(tag)).join(', ')}`);
  }
  
  logger.info(`Created: ${new Date(project.createdAt).toLocaleString()}`);
  logger.info(`Updated: ${new Date(project.updatedAt).toLocaleString()}`);

  if (project.stats) {
    logger.info('\n📊 Statistics:');
    logger.info(`Total Scans: ${project.stats.totalScans}`);
    logger.info(`Vulnerabilities: ${project.stats.vulnerabilityCount}`);
    
    if (project.stats.lastScanDate) {
      logger.info(`Last Scan: ${new Date(project.stats.lastScanDate).toLocaleString()}`);
    }
  }

  if (project.settings) {
    logger.info('\n⚙️ Settings:');
    logger.info(`Auto Scan: ${project.settings.autoScan ? '✅ Enabled' : '❌ Disabled'}`);
    
    if (project.settings.defaultScanners?.length) {
      logger.info(`Default Scanners: ${project.settings.defaultScanners.join(', ')}`);
    }
    
    if (project.settings.scanTriggers?.length) {
      logger.info(`Scan Triggers: ${project.settings.scanTriggers.join(', ')}`);
    }
  }
}

/**
 * Display project statistics
 */
function displayProjectStats(project: Project, logger: Logger): void {
  logger.info(`\n📊 Statistics for ${chalk.cyan(project.name)}:`);
  
  if (project.stats) {
    logger.info(`Total Scans: ${chalk.bold(project.stats.totalScans)}`);
    logger.info(`Vulnerabilities: ${chalk.red(project.stats.vulnerabilityCount)}`);
    
    if (project.stats.lastScanDate) {
      logger.info(`Last Scan: ${new Date(project.stats.lastScanDate).toLocaleString()}`);
    }
  } else {
    logger.info('No statistics available');
  }
}

/**
 * Display statistics for all projects
 */
function displayAllProjectsStats(projects: Project[], logger: Logger): void {
  logger.info('\n📊 Project Statistics Summary:\n');

  const totalProjects = projects.length;
  const totalScans = projects.reduce((sum, p) => sum + (p.stats?.totalScans || 0), 0);
  const totalVulnerabilities = projects.reduce((sum, p) => sum + (p.stats?.vulnerabilityCount || 0), 0);

  logger.info(`Total Projects: ${chalk.bold(totalProjects)}`);
  logger.info(`Total Scans: ${chalk.bold(totalScans)}`);
  logger.info(`Total Vulnerabilities: ${chalk.red(totalVulnerabilities)}`);

  if (projects.length > 0) {
    const table = new Table({
      head: ['Project', 'Scans', 'Vulnerabilities', 'Last Scan'],
      style: { head: ['cyan'] }
    });

    projects.forEach(project => {
      table.push([
        project.name,
        project.stats?.totalScans || '0',
        project.stats?.vulnerabilityCount || '0',
        project.stats?.lastScanDate 
          ? new Date(project.stats.lastScanDate).toLocaleDateString()
          : 'Never'
      ]);
    });

    console.log('\n' + table.toString());
  }
}