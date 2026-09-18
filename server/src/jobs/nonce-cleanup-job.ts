
import cron from 'node-cron';
import { NonceService } from '../services/nonce-service';
import { logger } from '../utils/logger';

export interface CleanupJobConfig {
  cronExpression?: string;
  runOnStartup?: boolean;
  environment?: 'production' | 'development' | 'test';
}

export interface CleanupJobResult {
  startTime: number;
  endTime: number;
  durationMs: number;
  noncesCleaned: number;
  success: boolean;
  error?: Error;
}

export class NonceCleanupJob {
  private static task: cron.ScheduledTask | null = null;
  private static isRunning = false;
  private static config: Required<CleanupJobConfig>;

  static initialize(config: CleanupJobConfig = {}): void {
    this.config = {
      cronExpression:
        config.cronExpression || this.getDefaultCronExpression(config.environment),
      runOnStartup: config.runOnStartup ?? false,
      environment: config.environment ?? 'production',
    };

    logger.info(`🔧 Initializing NonceCleanupJob in ${this.config.environment} mode`);
    logger.info(`   Cron expression: ${this.config.cronExpression}`);

    // Validate cron expression
    if (!cron.validate(this.config.cronExpression)) {
      throw new Error(
        `Invalid cron expression: ${this.config.cronExpression}`
      );
    }

    // Run on startup if configured
    if (this.config.runOnStartup) {
      this.run();
    }

    // Schedule the job
    this.task = cron.schedule(this.config.cronExpression, () => {
      this.run();
    });

    logger.info('✓ NonceCleanupJob scheduled successfully');
  }

  static async run(): Promise<CleanupJobResult> {
    // Prevent concurrent executions
    if (this.isRunning) {
      logger.warn('⚠️  Cleanup job is already running, skipping this execution');
      return {
        startTime: Date.now(),
        endTime: Date.now(),
        durationMs: 0,
        noncesCleaned: 0,
        success: false,
        error: new Error('Job already running'),
      };
    }

    this.isRunning = true;
    const startTime = Date.now();

    try {
      logger.info('🧹 Starting nonce cleanup job...');

      // Get metrics before cleanup
      const metricsBefore = await NonceService.getNonceMetrics();
      logger.info(`   Nonce count before cleanup: ${metricsBefore.total}`);
      logger.info(
        `   - Active: ${metricsBefore.active}, ` +
        `Expired: ${metricsBefore.expired}, ` +
        `Revoked: ${metricsBefore.revoked}, ` +
        `Used: ${metricsBefore.used}`
      );

      // Execute cleanup
      const noncesCleaned = await NonceService.cleanupExpiredNonces();

      // Get metrics after cleanup
      const metricsAfter = await NonceService.getNonceMetrics();
      logger.info(`   Nonce count after cleanup: ${metricsAfter.total}`);
      logger.info(
        `   - Active: ${metricsAfter.active}, ` +
        `Expired: ${metricsAfter.expired}, ` +
        `Revoked: ${metricsAfter.revoked}, ` +
        `Used: ${metricsAfter.used}`
      );

      const endTime = Date.now();
      const durationMs = endTime - startTime;

      logger.info(
        `✓ Cleanup job completed successfully ` +
        `(cleaned: ${noncesCleaned}, duration: ${durationMs}ms, ` +
        `requirement 10.1, 10.2, 10.5)`
      );

      return {
        startTime,
        endTime,
        durationMs,
        noncesCleaned,
        success: true,
      };
    } catch (error) {
      const endTime = Date.now();
      const durationMs = endTime - startTime;

      logger.error(
        `✗ Cleanup job failed after ${durationMs}ms: ${error instanceof Error ? error.message : String(error)}`
      );

      return {
        startTime,
        endTime,
        durationMs,
        noncesCleaned: 0,
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    } finally {
      this.isRunning = false;
    }
  }

  static stop(): void {
    if (this.task) {
      this.task.stop();
      // node-cron v3 doesn't have destroy(), just stop and clear reference
      this.task = null;
      logger.info('🛑 NonceCleanupJob stopped');
    }
  }

  private static getDefaultCronExpression(
    environment?: 'production' | 'development' | 'test'
  ): string {
    // Every 6 hours in production: 0 0 */6 * * * (00:00, 06:00, 12:00, 18:00 UTC)
    if (environment === 'production') {
      return '0 0 */6 * * *'; // Every 6 hours
    }

    // Every minute in development for faster testing
    if (environment === 'development' || environment === 'test') {
      return '* * * * *'; // Every minute
    }

    // Default to production schedule
    return '0 0 */6 * * *';
  }

  /**
   * Get the current configuration
   */
  static getConfig(): CleanupJobConfig | null {
    return this.config || null;
  }
}
