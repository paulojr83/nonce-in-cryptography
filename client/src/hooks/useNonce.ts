import { useContext } from 'react';
import { NonceContext, type NonceContextType } from '../contexts/NonceContext';

export function useNonce(): NonceContextType {
  const context = useContext(NonceContext);

  if (context === undefined) {
    throw new Error(
      'useNonce must be used inside a <NonceProvider>. Wrap your app in NonceProvider.'
    );
  }

  return context;
}

export default useNonce;
