<script lang="ts">
  const homeHref = '/#overview';
  const reportHref = 'https://github.com/VireonNoctis/PrivaCage/issues';
</script>

<svelte:head>
  <title>404 — Page not found | PrivaCage</title>
  <meta name="description" content="The requested PrivaCage page does not exist." />
  <meta name="robots" content="noindex, nofollow" />
</svelte:head>

<main class="not-found">
  <a class="not-found__brand" href="/" aria-label="PrivaCage home">
    <span aria-hidden="true">[</span> PRIVACAGE <span aria-hidden="true">]</span>
  </a>

  <section class="not-found__content" aria-labelledby="not-found-title">
    <p class="not-found__eyebrow">HTTP 404 / ROUTE NOT FOUND</p>
    <div class="not-found__code" aria-hidden="true">404</div>
    <h1 id="not-found-title">This address is outside the system.</h1>
    <p class="not-found__description">
      The page may have moved, the address may be incomplete, or it may never have existed.
    </p>
    <div class="not-found__actions">
      <a class="not-found__home" href={homeHref}>Return to overview <span aria-hidden="true">↗</span></a>
      <a class="not-found__github" href={reportHref}>Report a broken link</a>
    </div>
  </section>

  <footer class="not-found__footer">
    <span>PRIVACAGE / LOCAL-FIRST BY DESIGN</span>
    <span>STATUS: NO MATCH</span>
  </footer>
</main>

<style>
  :global(*) {
    box-sizing: border-box;
  }

  :global(html),
  :global(body),
  :global(#app) {
    min-width: 320px;
    min-height: 100%;
    margin: 0;
    background: #000;
  }

  :global(body) {
    color: #fff;
    font-family: ui-monospace, "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  }

  .not-found {
    display: flex;
    min-height: 100vh;
    flex-direction: column;
    padding: clamp(22px, 5vw, 64px);
    background: #000;
  }

  .not-found__brand,
  .not-found__footer,
  .not-found__eyebrow,
  .not-found__github {
    font-size: 10px;
    letter-spacing: .12em;
    text-decoration: none;
    text-transform: uppercase;
  }

  .not-found__brand {
    width: fit-content;
    color: #fff;
    font-weight: 700;
  }

  .not-found__brand span {
    color: #777;
  }

  .not-found__content {
    width: min(100%, 760px);
    margin: auto;
    padding: 10vh 0;
  }

  .not-found__eyebrow {
    margin: 0 0 25px;
    color: #888;
  }

  .not-found__code {
    color: #fff;
    font-size: clamp(96px, 22vw, 220px);
    font-weight: 700;
    letter-spacing: -.12em;
    line-height: .9;
  }

  h1 {
    max-width: 650px;
    margin: 32px 0 12px;
    color: #fff;
    font-size: clamp(25px, 4vw, 42px);
    font-weight: 500;
    letter-spacing: -.07em;
    line-height: 1.08;
  }

  .not-found__description {
    max-width: 480px;
    margin: 0;
    color: #929292;
    font-family: Inter, "Segoe UI", Arial, sans-serif;
    font-size: 14px;
    line-height: 1.7;
  }

  .not-found__actions {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 22px;
    margin-top: 34px;
  }

  .not-found__home {
    display: inline-flex;
    min-height: 46px;
    align-items: center;
    gap: 24px;
    padding: 0 17px;
    border: 1px solid #fff;
    color: #000;
    background: #fff;
    font-size: 11px;
    font-weight: 700;
    text-decoration: none;
    text-transform: uppercase;
  }

  .not-found__home:hover {
    color: #fff;
    background: #000;
  }

  .not-found__github {
    color: #aaa;
    text-decoration: underline;
    text-underline-offset: 4px;
  }

  .not-found__github:hover {
    color: #fff;
  }

  .not-found__footer {
    display: flex;
    justify-content: space-between;
    gap: 16px;
    padding-top: 16px;
    border-top: 1px solid #444;
    color: #777;
  }

  @media (max-width: 520px) {
    .not-found__footer {
      flex-direction: column;
    }

    .not-found__actions {
      align-items: flex-start;
      flex-direction: column;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      scroll-behavior: auto !important;
      transition-duration: 0.01ms !important;
    }
  }
</style>
