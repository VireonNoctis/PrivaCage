// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import NotFound from '../../main/interface/NotFound.svelte';

describe('PrivaCage custom 404 page', () => {
  it('ships the same branded 404 for static hosting', () => {
    const html = readFileSync(resolve(process.cwd(), 'public/404.html'), 'utf8');

    expect(html).toContain('<title>404 — Page not found | PrivaCage</title>');
    expect(html).toContain('<meta name="robots" content="noindex, nofollow"');
    expect(html).toContain('HTTP 404 / ROUTE NOT FOUND');
  });

  it('explains the missing route and provides a working home link', () => {
    render(NotFound);

    expect(screen.getByRole('heading', { name: 'This address is outside the system.' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /return to overview/i })).toHaveAttribute('href', '/#overview');
    expect(screen.getByRole('link', { name: /report a broken link/i })).toHaveAttribute(
      'href',
      'https://github.com/VireonNoctis/PrivaCage/issues'
    );
  });
});
