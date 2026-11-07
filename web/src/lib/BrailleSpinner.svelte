<script lang="ts">
  interface Props {
    label?: string;
  }

  let { label = "Loading" }: Props = $props();

  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
</script>

<span class="braille-spinner" role="status" aria-label={label}>
  <span class="braille-spinner__window" aria-hidden="true">
    <span class="braille-spinner__frames">
      {#each frames as frame, index (index)}
        <span>{frame}</span>
      {/each}
    </span>
  </span>
</span>

<style>
  .braille-spinner {
    display: inline-flex;
    width: 1.2em;
    height: 1.2em;
    flex: 0 0 1.2em;
    align-items: center;
    justify-content: center;
    overflow: hidden;
    color: #fff;
    font-family: ui-monospace, "SFMono-Regular", Consolas, monospace;
    line-height: 1.2;
    vertical-align: -0.12em;
  }

  .braille-spinner__window {
    display: block;
    width: 1em;
    height: 1.2em;
    overflow: hidden;
  }

  .braille-spinner__frames {
    display: flex;
    flex-direction: column;
    width: 100%;
    animation: braille-spinner-cycle 1s steps(10, end) infinite;
  }

  .braille-spinner__frames > span {
    display: block;
    width: 100%;
    height: 1.2em;
    flex: 0 0 1.2em;
    font-size: 1.2em;
    line-height: 1.2em;
    text-align: center;
  }

  @keyframes braille-spinner-cycle {
    to { transform: translateY(-90%); }
  }

  @media (prefers-reduced-motion: reduce) {
    .braille-spinner__frames {
      animation: none;
      transform: none;
    }
  }
</style>
