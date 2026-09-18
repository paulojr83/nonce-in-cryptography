interface EnvConfig {
  nodeEnv: 'development' | 'production' | 'test';
  port: number;
  databaseUrl: string;
  jwtSecret: string;
  sessionTtl: number;
  nonceTtl: number;
  nonceLength: number;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

const DEV_JWT_SECRET = 'dev-only-insecure-jwt-secret-do-not-use-in-production';

const readNumber = (key: string, fallback: number): number => {
  const value = process.env[key];
  if (value === undefined) return fallback;

  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
};

export const loadEnv = (): EnvConfig => {
  const nodeEnv = (process.env.NODE_ENV || 'development') as EnvConfig['nodeEnv'];
  const isProduction = nodeEnv === 'production';

  const jwtSecret = process.env.JWT_SECRET ?? (isProduction ? '' : DEV_JWT_SECRET);

  if (isProduction && jwtSecret.length < 32) {
    throw new Error(
      'JWT_SECRET must be set to at least 32 characters in production. ' +
        'Generate one with: openssl rand -hex 32'
    );
  }

  const config: EnvConfig = {
    nodeEnv,
    port: readNumber('PORT', 4000),
    databaseUrl: process.env.DATABASE_URL || 'http://localhost:3001',
    jwtSecret,
    sessionTtl: readNumber('SESSION_TTL', 86_400_000),
    nonceTtl: readNumber('NONCE_TTL', 300_000),
    nonceLength: readNumber('NONCE_LENGTH', 32),
    logLevel: (process.env.LOG_LEVEL || 'info') as EnvConfig['logLevel'],
  };

  if (config.nonceTtl < 60_000 || config.nonceTtl > 3_600_000) {
    throw new Error('NONCE_TTL must be between 60000ms (1 min) and 3600000ms (1 hour)');
  }

  if (config.nonceLength < 32) {
    throw new Error('NONCE_LENGTH must be at least 32 bytes');
  }

  return config;
};

let envConfig: EnvConfig | null = null;

export const getEnv = (): EnvConfig => {
  if (!envConfig) {
    envConfig = loadEnv();
  }
  return envConfig;
};

export default getEnv;
