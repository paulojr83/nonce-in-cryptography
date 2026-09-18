 
export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  data?: Record<string, unknown>;
  error?: Error;
}

class Logger {
  private currentLevel: LogLevel = LogLevel.INFO;

  setLevel(level: LogLevel): void {
    this.currentLevel = level;
  }

  private shouldLog(level: LogLevel): boolean {
    const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR];
    const currentIndex = levels.indexOf(this.currentLevel);
    const messageIndex = levels.indexOf(level);
    return messageIndex >= currentIndex;
  }

  private formatEntry(entry: LogEntry): string {
    const dataStr = entry.data ? ` ${JSON.stringify(entry.data)}` : '';
    const errorStr = entry.error ? ` ${entry.error.stack}` : '';
    return `[${entry.timestamp}] [${entry.level}] ${entry.message}${dataStr}${errorStr}`;
  }

  debug(message: string, data?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.DEBUG)) {
      const entry: LogEntry = {
        timestamp: new Date().toISOString(),
        level: LogLevel.DEBUG,
        message,
        data,
      };
      console.debug(this.formatEntry(entry));
    }
  }

  info(message: string, data?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.INFO)) {
      const entry: LogEntry = {
        timestamp: new Date().toISOString(),
        level: LogLevel.INFO,
        message,
        data,
      };
      console.info(this.formatEntry(entry));
    }
  }

  warn(message: string, data?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.WARN)) {
      const entry: LogEntry = {
        timestamp: new Date().toISOString(),
        level: LogLevel.WARN,
        message,
        data,
      };
      console.warn(this.formatEntry(entry));
    }
  }

  error(message: string, error?: Error, data?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.ERROR)) {
      const entry: LogEntry = {
        timestamp: new Date().toISOString(),
        level: LogLevel.ERROR,
        message,
        data,
        error,
      };
      console.error(this.formatEntry(entry));
    }
  }
}

export const logger = new Logger();
