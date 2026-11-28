import { describe, expect, it } from 'vitest';
import { isKnownPagePath } from '../../main/interface/routes';

describe('Svelte website route boundary', () => {
  it.each(['/', '/index.html', '/index.html/'])('keeps the application entry path %s', (path) => {
    expect(isKnownPagePath(path)).toBe(true);
  });

  it.each(['/not-found', '/dashboard', '/api/health', 'https://example.test/'])(
    'routes unknown paths to the custom 404 page: %s',
    (path) => {
      expect(isKnownPagePath(path)).toBe(false);
    }
  );
});
