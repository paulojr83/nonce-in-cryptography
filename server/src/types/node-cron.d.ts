declare module 'node-cron' {
  export interface ScheduleOptions {
    scheduled?: boolean;
    timezone?: string;
    name?: string;
    runOnInit?: boolean;
  }

  export interface ScheduledTask {
    start: () => void;
    stop: () => void;
    now?: () => void;
  }

  export function schedule(
    cronExpression: string,
    func: () => void | Promise<void>,
    options?: ScheduleOptions
  ): ScheduledTask;

  export function validate(cronExpression: string): boolean;

  export function getTasks(): Map<string, ScheduledTask>;
}
