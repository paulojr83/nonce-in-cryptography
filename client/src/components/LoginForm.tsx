import React, { useState } from 'react';
import { useAuth } from '../hooks/useAuth';

export interface LoginFormProps {
  onSuccess?: () => void;
}

function toUserMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);

  if (message.includes('Invalid email or password')) {
    return 'That email and password combination is not recognised.';
  }
  if (message.includes('Password is required')) {
    return 'Please enter your password.';
  }
  if (message.includes('Invalid email')) {
    return 'Please enter a valid email address.';
  }
  if (message.includes('Too many')) {
    return 'Too many attempts. Please wait a few minutes and try again.';
  }
  if (message.includes('Failed to fetch') || message.includes('NetworkError')) {
    return 'Could not reach the server. Check your connection and try again.';
  }

  return 'Sign in failed. Please try again.';
}

export const LoginForm: React.FC<LoginFormProps> = ({ onSuccess }) => {
  const { login, isLoading } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (event: React.FormEvent): Promise<void> => {
    event.preventDefault();
    setError(null);

    try {
      await login(email, password);
      onSuccess?.();
    } catch (loginError) {
      setError(toUserMessage(loginError));
    }
  };

  return (
    <form className="login-form" onSubmit={handleSubmit} noValidate>
      <h2>Sign in</h2>

      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      <label htmlFor="login-email">Email</label>
      <input
        id="login-email"
        name="email"
        type="email"
        autoComplete="username"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
        disabled={isLoading}
        required
      />

      <label htmlFor="login-password">Password</label>
      <input
        id="login-password"
        name="password"
        type="password"
        autoComplete="current-password"
        value={password}
        onChange={(event) => setPassword(event.target.value)}
        disabled={isLoading}
        required
      />

      <button type="submit" disabled={isLoading || !email || !password}>
        {isLoading ? 'Signing in...' : 'Sign in'}
      </button>
    </form>
  );
};

export default LoginForm;
