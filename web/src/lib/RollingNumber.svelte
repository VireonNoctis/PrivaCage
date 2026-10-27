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
  let wheelPositions = $state<number[]>([]);
  let wheelTransitionsEnabled = $state<boolean[]>([]);

  // Keep an extra cycle on either side so 9 -> 0 and 0 -> 9 roll naturally.
  const wheelDigits = Array.from({ length: 30 }, (_, index) => index % 10);
  let previousFormatted = '';
  let wheelPositionCache: number[] = [];

  function numericValue(text: string): number {
    const digits = text.replace(/\D/g, '');
    return digits ? Number(digits) : 0;
  }

  function handleWheelTransitionEnd(index: number, event: TransitionEvent): void {
    if (event.propertyName !== 'transform') return;

    const currentPosition = wheelPositions[index];
    if (currentPosition === undefined || (currentPosition >= 10 && currentPosition < 20)) {
      return;
    }

    // Re-center on an identical digit cycle without visually rolling ten places.
    const stablePosition = currentPosition >= 20 ? currentPosition - 10 : currentPosition + 10;
    wheelTransitionsEnabled = wheelTransitionsEnabled.map(
      (enabled, wheelIndex) => wheelIndex === index ? false : enabled
    );
    wheelPositions = wheelPositions.map(
      (position, wheelIndex) => wheelIndex === index ? stablePosition : position
    );
    wheelPositionCache = wheelPositionCache.map(
      (position, wheelIndex) => wheelIndex === index ? stablePosition : position
    );

    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        wheelTransitionsEnabled = wheelTransitionsEnabled.map(
          (enabled, wheelIndex) => wheelIndex === index ? true : enabled
        );
      });
    });
  }

  $effect(() => {
    const nextFormatted = formatted;
    if (!digitsReady || nextFormatted === previousFormatted) return;

    const previousCharacters = previousFormatted.split('').reverse();
    const nextCharacters = nextFormatted.split('').reverse();
    const movesForward = numericValue(nextFormatted) >= numericValue(previousFormatted);

    const nextPositions = nextCharacters.map((character, index) => {
      if (!/^\d$/.test(character)) return 0;

      const previousCharacter = previousCharacters[index];
      const previousPosition = wheelPositionCache[index] ?? (10 + Number(character));
      if (previousCharacter === undefined || !/^\d$/.test(previousCharacter)) {
        return 10 + Number(character);
      }

      const previousDigit = Number(previousCharacter);
      const nextDigit = Number(character);
      if (previousDigit === nextDigit) return previousPosition;

      if (movesForward) {
        return previousPosition + ((nextDigit - previousDigit + 10) % 10);
      }
      return previousPosition - ((previousDigit - nextDigit + 10) % 10);
    });

    previousFormatted = nextFormatted;
    wheelPositionCache = nextPositions;
    wheelPositions = nextPositions;
    wheelTransitionsEnabled = nextCharacters.map(() => true);
  });

  onMount(() => {
    const initialCharacters = formatted.split('').reverse();
    const initialPositions = initialCharacters.map((character) =>
      /^\d$/.test(character) ? 10 + Number(character) : 0
    );

    previousFormatted = formatted;
    wheelPositionCache = initialPositions;
    wheelPositions = initialPositions;
    wheelTransitionsEnabled = initialCharacters.map(() => true);

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
          style={`--digit-offset: ${digitsReady ? -(wheelPositions[reverseIndex] ?? 10) : -10}em`}
        >
          <span
            class="rolling-number__wheel"
            class:instant={wheelTransitionsEnabled[reverseIndex] === false}
            ontransitionend={(event) => handleWheelTransitionEnd(reverseIndex, event)}
          >
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
