// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import BrailleSpinner from './BrailleSpinner.svelte';

describe('BrailleSpinner', () => {
  it('exposes the current operation through an accessible status label', () => {
    render(BrailleSpinner, { label: 'Verifying audit signature' });

    expect(screen.getByRole('status', { name: 'Verifying audit signature' })).toBeInTheDocument();
  });

  it('provides a useful default label', () => {
    render(BrailleSpinner);

    expect(screen.getByRole('status', { name: 'Loading' })).toBeInTheDocument();
  });
});
