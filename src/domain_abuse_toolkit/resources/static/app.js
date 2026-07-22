document.documentElement.classList.add("js");

const languageForm = document.querySelector("[data-language-form]");
if (languageForm) {
  const returnField = languageForm.querySelector("[data-language-return]");
  const languageSelect = languageForm.querySelector("[data-language-select]");
  languageSelect?.addEventListener("change", () => {
    if (returnField) returnField.value = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    languageForm.requestSubmit();
  });
}

document.addEventListener("click", async (event) => {
  const emailLink = event.target.closest("[data-email-draft]");
  if (emailLink) {
    const recipientField = document.querySelector(emailLink.dataset.recipient);
    const subjectField = document.querySelector(emailLink.dataset.subject);
    const bodyField = document.querySelector(emailLink.dataset.body);
    if (recipientField?.value.trim()) {
      if (!recipientField.checkValidity()) {
        event.preventDefault();
        recipientField.reportValidity();
        return;
      }
      const recipient = encodeURIComponent(recipientField.value.trim()).replace("%40", "@");
      const query = new URLSearchParams({
        subject: subjectField?.value || "",
        body: bodyField?.value || "",
      });
      emailLink.href = `mailto:${recipient}?${query.toString()}`;
    }
  }

  const copyButton = event.target.closest("[data-copy]");
  if (copyButton) {
    const field = document.querySelector(copyButton.dataset.copy);
    if (!field) return;
    await navigator.clipboard.writeText(field.value);
    const previous = copyButton.textContent;
    copyButton.textContent = document.body.dataset.copiedLabel || "Copied";
    window.setTimeout(() => { copyButton.textContent = previous; }, 1200);
  }

  const tabButton = event.target.closest("[data-tab-target]");
  if (tabButton) {
    document.querySelectorAll(".tab-button").forEach((button) => button.classList.remove("active"));
    document.querySelectorAll(".draft").forEach((draft) => draft.classList.add("hidden"));
    tabButton.classList.add("active");
    document.getElementById(tabButton.dataset.tabTarget)?.classList.remove("hidden");
  }
});

const workflowRoot = document.querySelector("[data-workflow-root]");
if (workflowRoot) {
  const aliases = {
    collection: "evidence",
    "record-submission": "reporting",
  };
  const panels = [...workflowRoot.querySelectorAll("[data-workflow-panel]")];
  const steps = [...workflowRoot.querySelectorAll("[data-workflow-step]")];

  const showWorkflowStep = (requestedStep, focusPanel = false) => {
    const stepId = aliases[requestedStep] || requestedStep;
    const panel = panels.find((item) => item.dataset.workflowPanel === stepId);
    if (!panel) return false;

    workflowRoot.classList.add("workflow-enhanced");
    panels.forEach((item) => {
      item.hidden = item !== panel;
    });
    steps.forEach((item) => {
      const active = item.dataset.workflowStep === stepId;
      item.classList.toggle("active", active);
      if (active) item.setAttribute("aria-current", "step");
      else item.removeAttribute("aria-current");
    });
    if (focusPanel) panel.focus({ preventScroll: true });
    return true;
  };

  const showFromLocation = (focusPanel = false) => {
    const hashStep = window.location.hash.slice(1);
    const requested = hashStep === "actions"
      ? workflowRoot.dataset.defaultStep
      : hashStep;
    if (requested === "case-details") {
      document.getElementById("case-details")?.setAttribute("open", "");
      return;
    }
    if (!showWorkflowStep(requested, focusPanel)) {
      showWorkflowStep(workflowRoot.dataset.defaultStep || "overview", false);
    }
  };

  showFromLocation(false);
  window.addEventListener("hashchange", () => showFromLocation(true));
  document.addEventListener("click", (event) => {
    const link = event.target.closest("[data-workflow-link]");
    if (link && link.hash === window.location.hash) {
      showFromLocation(true);
    }
  });
}
