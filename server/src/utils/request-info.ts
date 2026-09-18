 
export interface RequestLike {
  headers?: {
    get?: (name: string) => string | null | undefined;
  };
}

 
export function getHeader(request: RequestLike | undefined, name: string): string | null {
  const get = request?.headers?.get;
  if (typeof get !== 'function') {
    return null;
  }

  const read = (key: string): string | null => {
    try {
      return get.call(request?.headers, key) ?? null;
    } catch {
      return null;
    }
  };

  return read(name) ?? read(name.toLowerCase()) ?? read(name.toUpperCase());
}
 
export function getIpAddress(request: RequestLike | undefined): string {
  const forwarded = getHeader(request, 'x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0]?.trim() || 'unknown';
  }

  const realIp = getHeader(request, 'x-real-ip');
  if (realIp) {
    return realIp;
  }

  return 'unknown';
}
 
export function getUserAgent(request: RequestLike | undefined): string {
  return getHeader(request, 'user-agent') || '';
}

 
export function getRequestInfo(request: RequestLike | undefined): {
  ipAddress: string;
  userAgent: string;
} {
  return {
    ipAddress: getIpAddress(request),
    userAgent: getUserAgent(request),
  };
}
