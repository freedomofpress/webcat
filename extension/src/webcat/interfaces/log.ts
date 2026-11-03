export type ConsoleLevel = "log" | "warn" | "error" | "info" | "debug";

// Log entries help track activities, including errors and warnings, by providing detailed context.
export interface LogEntry {
  timestamp: Date;
  tabId: number;
  origin: string;
  level: ConsoleLevel;
  message: string;
  stack?: string;
}
