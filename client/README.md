# Nonce Crypto Todo Client

React/Relay frontend for the nonce-based cryptographic authentication todo application.

## Overview

This is a modern React application built with:
- **React 18**: UI library
- **Relay**: GraphQL client for data fetching with automatic caching
- **Vite**: Fast build tool and dev server
- **TypeScript**: Type safety for React components
- **Vitest**: Unit testing framework

## Project Structure

```
client/
├── src/
│   ├── main.tsx              # Vite entry point
│   ├── App.tsx               # Root component
│   ├── index.css             # Global styles
│   ├── test/
│   │   └── setup.ts          # Test configuration
│   ├── contexts/             # React Context (created in tasks 23-24)
│   │   ├── NonceContext.tsx  # Nonce state management
│   │   └── AuthContext.tsx   # Authentication state
│   ├── hooks/                # Custom React hooks
│   │   ├── useNonce.ts       # Nonce context hook
│   │   ├── useAuth.ts        # Auth context hook
│   │   ├── useNonceMutation.ts # Relay mutation with retry
│   │   └── __tests__/
│   ├── relay/                # Relay environment and config
│   │   ├── environment.ts    # Relay store setup
│   │   └── nonce-middleware.ts
│   ├── components/           # React components
│   │   ├── LoginForm.tsx
│   │   ├── TodoList.tsx
│   │   ├── CreateTodoForm.tsx
│   │   ├── TodoItem.tsx
│   │   ├── NonceErrorBoundary.tsx
│   │   └── __tests__/
│   ├── graphql/              # GraphQL operations
│   │   ├── queries/
│   │   │   ├── GetTodosQuery.graphql
│   │   │   └── GetMeQuery.graphql
│   │   └── mutations/
│   │       ├── LoginMutation.graphql
│   │       ├── CreateTodoMutation.graphql
│   │       ├── UpdateTodoMutation.graphql
│   │       └── DeleteTodoMutation.graphql
│   └── __generated__/        # Relay generated types (auto)
├── public/
│   └── index.html            # HTML template
├── .graphqlconfig.yml        # GraphQL tooling config
├── relay.config.js           # Relay compiler config
├── vite.config.ts            # Vite build config
├── vitest.config.ts          # Test runner config
├── tsconfig.json             # TypeScript config
└── package.json              # Dependencies
```

## Setup

### Install Dependencies

From the project root:
```bash
npm install
```

This installs dependencies for both `server` and `client` workspaces.

### Development

Start the dev server with hot module replacement:
```bash
npm run dev --workspace=client
```

Or from the client directory:
```bash
npm run dev
```

The app will be available at `http://localhost:3000`.

The dev server proxies `/graphql` requests to `http://localhost:4000` (the Yoga server).

### GraphQL Schema

Generate the GraphQL schema from the server:
```bash
npm run relay --workspace=client
```

This requires the Yoga server to be running on `http://localhost:4000`.

### Testing

Run tests in watch mode:
```bash
npm run test --workspace=client
```

Run tests once:
```bash
npm run test:run --workspace=client
```

View test UI:
```bash
npm run test:ui --workspace=client
```

### Build

Build for production:
```bash
npm run build --workspace=client
```

Preview production build:
```bash
npm run preview --workspace=client
```

## Key Concepts

### Nonce Management

Nonces are cryptographic tokens used to prevent CSRF and replay attacks. This application:

1. Fetches a fresh nonce after login
2. Includes the nonce in every mutation request via the `X-NONCE` header
3. Updates the stored nonce when receiving a fresh one in the response
4. Automatically retries mutations if nonce validation fails

### Relay Integration

Relay is a GraphQL client that provides:
- **Automatic caching**: Results cached based on queries and variables
- **Normalized store**: Updates automatically reflected across the app
- **Type safety**: Generated TypeScript types for all queries and mutations
- **Connection handling**: Built-in pagination support

### React Context

Two context providers manage global state:
- **NonceContext**: Current nonce, refresh logic, error handling
- **AuthContext**: User info, session token, login/logout

## Implementation Phases

This client is built incrementally across multiple implementation phases:

- **Phase 7 (Tasks 23-27)**: Setup Nonce and Auth contexts, Relay environment
- **Phase 8 (Tasks 28-33)**: Components and mutations with nonce integration
- **Phase 9 (Tasks 34-35)**: GraphQL operation definitions
- **Phase 10 (Task 36)**: Checkpoint - Frontend architecture complete
- **Phase 12 (Tasks 49-56)**: Unit and integration testing

## Environment Variables

Create a `.env.local` file for development:

```
VITE_API_URL=http://localhost:4000/graphql
VITE_SESSION_STORAGE_KEY=nonce-app-session
```

## Troubleshooting

### Cannot find GraphQL schema

Ensure the Yoga server is running and accessible at `http://localhost:4000/graphql`, then:
```bash
npm run relay --workspace=client
```

### Relay compiler errors

Clear the `__generated__` directory and regenerate:
```bash
rm -rf src/__generated__
npm run relay --workspace=client
```

### Hot reload not working

Kill the dev server and restart:
```bash
npm run dev --workspace=client
```

## Security Considerations

- ✅ Nonces transmitted only over HTTPS in production
- ✅ Session tokens stored in sessionStorage (cleared on browser close)
- ✅ Never expose plaintext nonces in logs or error messages
- ✅ GraphQL schema introspection disabled in production (optional)

## Resources

- [React Documentation](https://react.dev)
- [Relay Documentation](https://relay.dev)
- [Vite Documentation](https://vitejs.dev)
- [TypeScript Documentation](https://www.typescriptlang.org)
