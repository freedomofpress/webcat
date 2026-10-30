import { RequestDetails } from "../browser/requests";
import { LogEntry } from "./interfaces/log";
import { Stateful } from "./interfaces/requeststate";

type ConsoleLevel = "log" | "warn" | "error" | "info" | "debug";
// Capped to avoid long running browser sessions to grow forever
const MAX_LOGS = 1000;
const globalLogs: LogEntry[] = [];

// Logger Class
class Logger {
  // Controls if log/debug/info lines are printed; warn/error always are
  private debugMode: boolean =
    import.meta.env.DEV || !!import.meta.env.VITE_TESTING;

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
   * @param tabId - The tab ID associated with the log, or -1 if none.
   * @param origin - The origin of the log (e.g., URL or script).
   * @param cause - Optional caught error whose stack is recorded.
   */
  public addLog(
    level: ConsoleLevel,
    message: string,
    tabId = -1,
    origin = "",
    cause?: unknown,
  ): void {
    const stack =
      cause === undefined
        ? undefined
        : cause instanceof Error
          ? cause.stack
          : String(cause);
    const logEntry: LogEntry = {
      timestamp: new Date(),
      tabId,
      origin,
      level,
      message,
      stack,
    };

    globalLogs.push(logEntry);
    if (globalLogs.length > MAX_LOGS) {
      globalLogs.shift();
    }

    if (this.shouldPrint(level)) {
      const tab = tabId > 0 ? `Tab ${tabId}` : "worker";
      const where = origin ? ` [${origin}]` : "";
      console[level](
        `[WEBCAT] [${logEntry.timestamp.toISOString()}] [${tab}]${where} ${message}` +
          (stack ? `\n${stack}` : ""),
      );
    }
  }

  /** Adds a log entry with the default level. */
  public log(message: string, details?: Stateful<RequestDetails>) {
    this.#emit("log", message, details);
  }

  /** Adds a warning log entry. */
  public warn(
    message: string,
    details?: Stateful<RequestDetails>,
    cause?: unknown,
  ) {
    this.#emit("warn", message, details, cause);
  }

  /** Adds an error log entry. */
  public error(
    message: string,
    details?: Stateful<RequestDetails>,
    cause?: unknown,
  ) {
    this.#emit("error", message, details, cause);
  }

  /** Adds an informational log entry. */
  public info(message: string, details?: Stateful<RequestDetails>) {
    this.#emit("info", message, details);
  }

  /** Add a debug log entry. */
  public debug(message: string, details?: Stateful<RequestDetails>) {
    this.#emit("debug", message, details);
  }

  #emit(
    level: ConsoleLevel,
    message: string,
    details?: Stateful<RequestDetails>,
    cause?: unknown,
  ) {
    this.addLog(level, message, details?.tabId, details?.state.fqdn, cause);
  }

  /**
   * Determine if a log should be printed based on the debug mode and log level.
   * @param level - Log level to check.
   */
  private shouldPrint(level: ConsoleLevel): boolean {
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
   * Clear all logs.
   */
  public clearLogs(): void {
    globalLogs.length = 0;
  }
}

// Export logger and global logs
/** @internal */
export const logger = new Logger();
/** @internal */
export { globalLogs };
