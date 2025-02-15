export enum LogType {
  debug = "debug",
  info = "info",
  warning = "warning",
  error = "error",
}

// Log entries help track activities, including errors and warnings, by providing detailed context.
export interface LogEntry {
  timestamp: Date;
  tabId: number;
  origin: string;
  level: keyof Console; // Ensures valid console log levels
  message: string;
  stack?: string;
}
