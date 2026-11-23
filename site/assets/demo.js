// Plays the web UI recording while it is on screen, unless the reader asked
// for reduced motion. Without this script the video still has its controls.
(() => {
  const v = document.querySelector('.demo video');
  if (!v || !('IntersectionObserver' in window) || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) v.play().catch(() => {});
      else v.pause();
    }
  }, { threshold: 0.5 }).observe(v);
})();
