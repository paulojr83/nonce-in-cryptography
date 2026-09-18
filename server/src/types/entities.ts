export interface Nonce {
  id: string;
  user_id: string;
  session_id: string;
  nonce_hash: string;
  created_at: number;
  expires_at: number;
  status: 'active' | 'expired' | 'revoked';
  used: boolean;
  consumed_at: number | null;
  /**
   * Set only on a login challenge, which carries the key agreed before there
   * is a session to hang it on. Every other nonce takes its session's key.
   */
  transport_key?: string | null;
  ip_address: string;
  user_agent_hash: string;
}

export interface User {
  id: string;
  email: string;
  /**
   * sha256(username:realm:password) - the verifier for challenge-response
   * login. Not a password hash in the bcrypt sense: it is what the server
   * needs to recompute a digest it did not choose the inputs for, which means
   * it is password-equivalent. See digest-service.ts.
   */
  digest_ha1: string;
  created_at: number;
  last_login: number | null;
  active_sessions: string[];
  security_metadata: {
    failed_login_attempts: number;
    last_failed_attempt: number | null;
    account_locked: boolean;
  };
}

export interface Session {
  id: string;
  user_id: string;
  created_at: number;
  expires_at: number;
  last_activity: number;
  status: 'active' | 'expired' | 'revoked';
  token: string;
  /** ECDH secret agreed at login, hex. Null for a session with no handshake. */
  transport_key: string | null;
}

export interface Todo {
  id: string;
  user_id: string;
  title: string;
  description: string | null;
  completed: boolean;
  created_at: number;
  updated_at: number;
  created_by_nonce_id: string;
}

/**
 * A loose filter document, in the shape a document store would take:
 * `{ user_id: 'u1' }`, `{ expires_at: { $lt: 123 } }`, `{ status: { $in: [...] } }`.
 *
 * `any` is deliberate. The values are a field's own type or an operator object,
 * and narrowing that here would push casts into every call site for no safety
 * the repositories do not already enforce when they read it.
 */
export interface QueryFilter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

/** A partial record, keyed by field name. `any` for the same reason. */
export interface UpdateOptions {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}
