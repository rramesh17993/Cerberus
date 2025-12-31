/**
 * Logger utility for SecureScan CLI
 * 
 * Provides structured logging with different levels and colored output.
 * Supports both console and file logging with configurable formatting.
 */

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4
}

export interface LoggerOptions {
  level?: LogLevel;
  enableColors?: boolean;
  enableTimestamp?: boolean;
  logFile?: string;
}

// Color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  bold: '\x1b[1m',
  dim: '\x1b[2m'
};

// Icons for different log levels
const icons = {
  debug: '🔍',
  info: '📋',
  warn: '⚠️',
  error: '❌',
  success: '✅'
};

export class Logger {
  private level: LogLevel;
  private enableColors: boolean;
  private enableTimestamp: boolean;
  private logFile?: string;

  constructor(options: LoggerOptions | boolean = {}) {
    // Handle legacy boolean parameter for verbose mode
    if (typeof options === 'boolean') {
      options = { level: options ? LogLevel.DEBUG : LogLevel.INFO };
    }

    this.level = options.level ?? LogLevel.INFO;
    this.enableColors = options.enableColors ?? this.supportsColor();
    this.enableTimestamp = options.enableTimestamp ?? false;
    this.logFile = options.logFile;
  }

  /**
   * Debug level logging
   */
  debug(message: string, ...args: any[]): void {
    this.log(LogLevel.DEBUG, 'debug', message, ...args);
  }

  /**
   * Info level logging
   */
  info(message: string, ...args: any[]): void {
    this.log(LogLevel.INFO, 'info', message, ...args);
  }

  /**
   * Warning level logging
   */
  warn(message: string, ...args: any[]): void {
    this.log(LogLevel.WARN, 'warn', message, ...args);
  }

  /**
   * Error level logging
   */
  error(message: string, ...args: any[]): void {
    this.log(LogLevel.ERROR, 'error', message, ...args);
  }

  /**
   * Success logging (info level with success styling)
   */
  success(message: string, ...args: any[]): void {
    if (this.level <= LogLevel.INFO) {
      const formattedMessage = this.formatMessage('success', message, ...args);
      console.log(formattedMessage);
      this.writeToFile('info', message, ...args);
    }
  }

  /**
   * Generic logging method
   */
  private log(level: LogLevel, type: keyof typeof icons, message: string, ...args: any[]): void {
    if (this.level <= level) {
      const formattedMessage = this.formatMessage(type, message, ...args);
      
      // Output to appropriate stream
      if (level >= LogLevel.WARN) {
        console.error(formattedMessage);
      } else {
        console.log(formattedMessage);
      }
      
      // Write to log file if configured
      this.writeToFile(type, message, ...args);
    }
  }

  /**
   * Format log message with colors, timestamp, and icons
   */
  private formatMessage(type: keyof typeof icons, message: string, ...args: any[]): string {
    let formatted = '';

    // Add timestamp if enabled
    if (this.enableTimestamp) {
      const timestamp = new Date().toISOString();
      formatted += this.enableColors 
        ? `${colors.gray}[${timestamp}]${colors.reset} `
        : `[${timestamp}] `;
    }

    // Add icon
    formatted += `${icons[type]} `;

    // Add message with appropriate color
    if (this.enableColors) {
      const messageColor = this.getMessageColor(type);
      formatted += `${messageColor}${message}${colors.reset}`;
    } else {
      formatted += message;
    }

    // Add additional arguments
    if (args.length > 0) {
      const argsString = args.map(arg => {
        if (typeof arg === 'object') {
          return JSON.stringify(arg, null, 2);
        }
        return String(arg);
      }).join(' ');
      
      formatted += ` ${argsString}`;
    }

    return formatted;
  }

  /**
   * Get color for message type
   */
  private getMessageColor(type: keyof typeof icons): string {
    switch (type) {
      case 'debug': return colors.gray;
      case 'info': return colors.blue;
      case 'warn': return colors.yellow;
      case 'error': return colors.red;
      case 'success': return colors.green;
      default: return colors.reset;
    }
  }

  /**
   * Write to log file if configured
   */
  private async writeToFile(type: string, message: string, ...args: any[]): Promise<void> {
    if (!this.logFile) return;

    try {
      const fs = await import('fs/promises');
      const timestamp = new Date().toISOString();
      const argsString = args.length > 0 ? ` ${args.join(' ')}` : '';
      const logEntry = `[${timestamp}] ${type.toUpperCase()}: ${message}${argsString}\n`;
      
      await fs.appendFile(this.logFile, logEntry, 'utf-8');
    } catch (error) {
      // Fail silently to avoid logging loops
    }
  }

  /**
   * Check if terminal supports color output
   */
  private supportsColor(): boolean {
    try {
      // Check if we're in a TTY and have color support
      return !!(
        process.stdout.isTTY &&
        (process.env.COLORTERM ||
         process.env.TERM === 'color' ||
         process.env.TERM?.includes('color') ||
         process.env.TERM?.includes('256'))
      );
    } catch {
      return false;
    }
  }

  /**
   * Set log level
   */
  setLevel(level: LogLevel): void {
    this.level = level;
  }

  /**
   * Enable/disable color output
   */
  setColors(enabled: boolean): void {
    this.enableColors = enabled;
  }

  /**
   * Enable/disable timestamp
   */
  setTimestamp(enabled: boolean): void {
    this.enableTimestamp = enabled;
  }

  /**
   * Set log file
   */
  setLogFile(filePath: string): void {
    this.logFile = filePath;
  }

  /**
   * Create a child logger with a prefix
   */
  child(prefix: string): Logger {
    const childLogger = new Logger({
      level: this.level,
      enableColors: this.enableColors,
      enableTimestamp: this.enableTimestamp,
      logFile: this.logFile
    });

    // Override the formatMessage method to include prefix
    const originalFormatMessage = childLogger['formatMessage'].bind(childLogger);
    childLogger['formatMessage'] = (type: keyof typeof icons, message: string, ...args: any[]) => {
      return originalFormatMessage(type, `[${prefix}] ${message}`, ...args);
    };

    return childLogger;
  }

  /**
   * Create logger with specific configuration
   */
  static create(options: LoggerOptions = {}): Logger {
    return new Logger(options);
  }

  /**
   * Create verbose logger
   */
  static verbose(): Logger {
    return new Logger({
      level: LogLevel.DEBUG,
      enableTimestamp: true
    });
  }

  /**
   * Create silent logger
   */
  static silent(): Logger {
    return new Logger({
      level: LogLevel.SILENT
    });
  }

  /**
   * Create file logger
   */
  static file(filePath: string, level: LogLevel = LogLevel.INFO): Logger {
    return new Logger({
      level,
      logFile: filePath,
      enableColors: false,
      enableTimestamp: true
    });
  }
}

// Helper function to create a logger with color methods
export function createColoredLogger(): Logger & {
  red: (message: string) => void;
  green: (message: string) => void;
  yellow: (message: string) => void;
  blue: (message: string) => void;
  cyan: (message: string) => void;
  magenta: (message: string) => void;
  bold: (message: string) => void;
  dim: (message: string) => void;
} {
  const logger = new Logger();

  // Add color methods
  (logger as any).red = (message: string) => {
    console.log(`${colors.red}${message}${colors.reset}`);
  };

  (logger as any).green = (message: string) => {
    console.log(`${colors.green}${message}${colors.reset}`);
  };

  (logger as any).yellow = (message: string) => {
    console.log(`${colors.yellow}${message}${colors.reset}`);
  };

  (logger as any).blue = (message: string) => {
    console.log(`${colors.blue}${message}${colors.reset}`);
  };

  (logger as any).cyan = (message: string) => {
    console.log(`${colors.cyan}${message}${colors.reset}`);
  };

  (logger as any).magenta = (message: string) => {
    console.log(`${colors.magenta}${message}${colors.reset}`);
  };

  (logger as any).bold = (message: string) => {
    console.log(`${colors.bold}${message}${colors.reset}`);
  };

  (logger as any).dim = (message: string) => {
    console.log(`${colors.dim}${message}${colors.reset}`);
  };

  return logger as any;
}