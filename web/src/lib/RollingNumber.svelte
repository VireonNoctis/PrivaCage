<script lang="ts">
  import { onMount } from 'svelte';

  interface Props {
    value: number | string;
    reducedMotion?: boolean;
    announce?: boolean;
  }

  let { value, reducedMotion = false, announce = true }: Props = $props();
  let formatted = $derived(
    typeof value === 'number' ? new Intl.NumberFormat('en-US').format(value) : value
  );
  let digitsReady = $state(false);

  // Start every wheel on zero, then roll into the real value after the first paint.
  // The three repeated cycles keep the target digit centered inside the clipped wheel.
  const wheelDigits = Array.from({ length: 30 }, (_, index) => index % 10);

  onMount(() => {
    if (reducedMotion || typeof window.requestAnimationFrame !== 'function') {
      digitsReady = true;
      return;
    }

    const frame = window.requestAnimationFrame(() => {
      digitsReady = true;
    });

    return () => window.cancelAnimationFrame(frame);
  });
</script>

<span
  class="rolling-number"
  class:reduced-motion={reducedMotion}
  aria-label={formatted}
  aria-live={announce ? 'polite' : 'off'}
  aria-atomic="true"
>
  <span class="sr-only">{formatted}</span>
  <span class="rolling-number__digits" aria-hidden="true">
    {#each formatted.split('').reverse() as character, reverseIndex (reverseIndex)}
      {#if /^\d$/.test(character)}
        <span
          class="rolling-number__digit"
          style={`--digit-offset: ${digitsReady ? -(10 + Number(character)) : -10}em`}
        >
          <span class="rolling-number__wheel">
            {#each wheelDigits as wheelDigit, wheelIndex (wheelIndex)}
              <span>{wheelDigit}</span>
            {/each}
          </span>
        </span>
      {:else}
        <span class="rolling-number__separator">{character}</span>
      {/if}
    {/each}
  </span>
</span>
