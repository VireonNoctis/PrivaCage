<script lang="ts">
  import { fly } from 'svelte/transition';

  interface Props {
    value: number;
    reducedMotion?: boolean;
  }

  let { value, reducedMotion = false }: Props = $props();
  let formatted = $derived(new Intl.NumberFormat('en-US').format(value));
</script>

<span class="rolling-number" aria-label={formatted} aria-live="polite" aria-atomic="true">
  <span class="sr-only">{formatted}</span>
  <span class="rolling-number__digits" aria-hidden="true">
    {#each formatted.split('') as digit, index (index + '-' + digit)}
      <span
        class="rolling-number__digit"
        in:fly={{ y: reducedMotion ? 0 : 8, duration: reducedMotion ? 0 : 180 }}
        out:fly={{ y: reducedMotion ? 0 : -8, duration: reducedMotion ? 0 : 130 }}
      >{digit}</span>
    {/each}
  </span>
</span>
