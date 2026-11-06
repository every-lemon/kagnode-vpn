/* KagNode theme preference. Credentials never enter this script. */
(() => {
  const start = () => {
    const root = document.documentElement;
    try {
      const stored = localStorage.getItem("kagnode.theme");
      if (["light", "dark"].includes(stored)) root.dataset.theme = stored;
    } catch {}
    const buttons = [...document.querySelectorAll("[data-kn-theme]")];
    const current = () =>
      root.dataset.theme ||
      (matchMedia("(prefers-color-scheme:light)").matches ? "light" : "dark");
    const reflect = () =>
      buttons.forEach((button) => {
        button.textContent =
          current() === "dark" ? "Light appearance" : "Dark appearance";
        button.setAttribute(
          "aria-label",
          "Switch to " +
            (current() === "dark" ? "light" : "dark") +
            " appearance",
        );
      });
    buttons.forEach((button) =>
      button.addEventListener("click", () => {
        root.dataset.theme = current() === "dark" ? "light" : "dark";
        try {
          localStorage.setItem("kagnode.theme", root.dataset.theme);
        } catch {}
        reflect();
      }),
    );
    reflect();
  };
  document.readyState === "loading"
    ? document.addEventListener("DOMContentLoaded", start, { once: true })
    : start();
})();
