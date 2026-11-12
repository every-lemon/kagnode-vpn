/* KagNode VPN: fresh provider identity, existing local MFA and roles. */
(() => {
  const box = document.getElementById("provider-login");
  if (!box) return;
  let issuer = "https://nebulacoder.com",
    ready = false;
  let csrf = "",
    enabled = false,
    attempt = "";
  async function request(action, data = {}) {
    if (action === "start") {
      const response = await fetch("/manage/kagnode-login", {
        cache: "no-store",
        credentials: "same-origin",
      });
      if (!response.ok) throw Error("Sign-in is unavailable.");
      const state = await response.json();
      csrf = state.csrf;
      enabled = state.enabled === true;
    }
    const response = await fetch("/manage/kagnode-login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ action, ...data }),
    });
    const result = await response.json();
    if (!response.ok) throw Error(result.error || "Unable to sign in.");
    return result;
  }
  window.KagNodeLoginHost = {
    state: () => ({ issuer, ready, enabled }),
    request,
    complete: (result) => {
      if (result.continuation !== "mfa") throw Error("Invalid continuation.");
      attempt = result.attempt_id;
      const form = document.getElementById("provider-mfa");
      form.hidden = false;
      form.elements.code.focus();
    },
  };
  document
    .getElementById("provider-mfa")
    .addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget,
        button = form.querySelector("button"),
        error = document.getElementById("provider-error");
      button.disabled = true;
      error.textContent = "";
      try {
        const result = await request("complete", {
          attempt_id: attempt,
          code: form.elements.code.value,
        });
        if (
          result.continuation !== "signed_in" ||
          result.redirect !== "/manage"
        )
          throw Error("Invalid continuation.");
        form.elements.code.value = "";
        location.assign("/manage");
      } catch (failure) {
        error.textContent = failure.message;
      } finally {
        button.disabled = false;
      }
    });
  fetch("/manage/kagnode-login", {
    cache: "no-store",
    credentials: "same-origin",
  })
    .then((response) => (response.ok ? response.json() : null))
    .then((state) => {
      issuer = state?.issuer || "https://nebulacoder.com";
      ready = true;
      enabled = state?.enabled === true;
      csrf = state?.csrf || "";
      box.hidden = !enabled;
      window.KagNodeLogin?.refresh();
    })
    .catch(() => {});
})();
