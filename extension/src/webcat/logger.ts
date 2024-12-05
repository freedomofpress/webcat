import { LogEntry } from "./interfaces";

const globalLogs: LogEntry[] = [];

// Logger Class
class Logger {
  private debugMode: boolean = true; // Controls if debug/info logs are printed

  /**
   * Enable or disable debug mode.
   * @param enabled - Whether debug mode is enabled.
   */
  public setDebugMode(enabled: boolean): void {
    this.debugMode = enabled;
  }

  /**
   * Add a log entry.
   * @param level - Log level (debug, info, warn, error).
   * @param message - The log message.
   * @param tabId - The tab ID associated with the log.
   * @param origin - The origin of the log (e.g., URL or script).
   * @param stack - Optional stack trace.
   */
  public addLog(
    level: keyof Console,
    message: string,
    tabId: number,
    origin: string,
    stack?: string,
  ): void {
    const logEntry: LogEntry = {
      timestamp: new Date(),
      tabId,
      origin,
      level,
      message,
      stack,
    };

    // Store log in the global log array
    globalLogs.push(logEntry);

    // Conditional console output
    if (this.shouldPrint(level)) {
      // Cast console[level] to a function type
      (console[level] as (...args: any[]) => void)(
        `[${logEntry.timestamp.toISOString()}] [Tab ${logEntry.tabId}] [${logEntry.origin}] ${logEntry.message}`,
        stack || "",
      );
    }
  }

  /**
   * Determine if a log should be printed based on the debug mode and log level.
   * @param level - Log level to check.
   */
  private shouldPrint(level: keyof Console): boolean {
    if (level === "warn" || level === "error") {
      return true; // Always print warnings and errors
    }
    return this.debugMode; // Print debug/info only if debugMode is enabled
  }

  /**
   * Get all log entries.
   */
  public getLogs(): LogEntry[] {
    return [...globalLogs];
  }

  /**
   * Get logs filtered by level.
   * @param level - Log level to filter by (debug, info, warn, error).
   */
  public getLogsByLevel(level: keyof Console): LogEntry[] {
    return globalLogs.filter((log) => log.level === level);
  }

  /**
   * Get logs filtered by tab ID.
   * @param tabId - Tab ID to filter by.
   */
  public getLogsByTab(tabId: number): LogEntry[] {
    return globalLogs.filter((log) => log.tabId === tabId);
  }

  /**
   * Get logs filtered by origin.
   * @param origin - Origin (e.g., URL or script) to filter by.
   */
  public getLogsByOrigin(origin: string): LogEntry[] {
    return globalLogs.filter((log) => log.origin === origin);
  }

  /**
   * Clear all logs.
   */
  public clearLogs(): void {
    globalLogs.length = 0;
  }
}

// Export logger and global logs
export const logger = new Logger();
export { globalLogs };
