// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import NotFound from '../../main/interface/NotFound.svelte';

describe('PrivaCage custom 404 page', () => {
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
