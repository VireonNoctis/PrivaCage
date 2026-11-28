const KNOWN_PAGE_PATHS = new Set(['/', '/index.html']);

export function isKnownPagePath(pathname: string): boolean {
  if (!pathname.startsWith('/')) return false;
  let normalized = pathname;
  while (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }
  return KNOWN_PAGE_PATHS.has(normalized);
}
