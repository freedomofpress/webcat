// Log entries help track activities, including errors and warnings, by providing detailed context.
export interface LogEntry {
  timestamp: Date;
  tabId: number;
  origin: string;
  level: "log" | "warn" | "error" | "info" | "debug";
  message: string;
  stack?: string;
}
