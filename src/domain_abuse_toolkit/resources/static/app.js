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

const collectionDialog = document.querySelector("[data-collection-dialog]");
if (collectionDialog) {
  const message = collectionDialog.querySelector("[data-collection-message]");
  const finishLink = collectionDialog.querySelector("[data-collection-finish]");
  const closeButton = collectionDialog.querySelector("[data-collection-close]");
  const liveIndicator = collectionDialog.querySelector("[data-collection-live]");
  const stageElements = [...collectionDialog.querySelectorAll("[data-collection-stage]")];
  const labels = {
    pending: collectionDialog.dataset.statusPending,
    running: collectionDialog.dataset.statusRunning,
    complete: collectionDialog.dataset.statusComplete,
    warning: collectionDialog.dataset.statusWarning,
    failed: collectionDialog.dataset.statusFailed,
  };

  const setStageState = (element, state) => {
    element.classList.remove("stage-pending", "stage-running", "stage-complete", "stage-warning", "stage-failed");
    element.classList.add(`stage-${state}`);
    const marker = element.querySelector(".collection-stage-marker");
    const status = element.querySelector("[data-stage-status]");
    if (marker && state === "complete") marker.textContent = "✓";
    if (marker && state === "warning") marker.textContent = "!";
    if (marker && state === "failed") marker.textContent = "×";
    if (status) status.textContent = labels[state] || state;
  };

  const resultState = (statuses) => {
    if (statuses.some((status) => status === "failed")) return "failed";
    if (statuses.some((status) => ["partial", "skipped"].includes(status))) return "warning";
    return statuses.length ? "complete" : "warning";
  };

  const renderTerminalStages = (payload) => {
    const byCollector = new Map(payload.results.map((item) => [item.collector, item.status]));
    stageElements.forEach((element) => {
      const stage = element.dataset.collectionStage;
      if (stage === "persisting") {
        setStageState(
          element,
          payload.job.completed_stages.includes("persisting") ? "complete" : "failed",
        );
      } else if (stage === "http_tls") {
        setStageState(element, resultState([byCollector.get("http"), byCollector.get("tls")].filter(Boolean)));
      } else {
        setStageState(element, resultState([byCollector.get(stage)].filter(Boolean)));
      }
    });
  };

  const renderProgress = (payload) => {
    if (payload.terminal) {
      renderTerminalStages(payload);
      if (message) {
        message.textContent = payload.outcome === "complete"
          ? collectionDialog.dataset.completeMessage
          : payload.outcome === "usable_with_limits"
            ? collectionDialog.dataset.limitedMessage
            : collectionDialog.dataset.failedMessage;
      }
      liveIndicator?.classList.add("is-complete");
      finishLink?.classList.remove("hidden");
      if (closeButton) closeButton.hidden = true;
      if (!collectionDialog.open && collectionDialog.showModal) {
        collectionDialog.showModal();
      }
      return true;
    }

    const completed = new Set(payload.job.completed_stages);
    stageElements.forEach((element) => {
      const stage = element.dataset.collectionStage;
      setStageState(
        element,
        completed.has(stage)
          ? "complete"
          : stage === payload.job.current_stage
            ? "running"
            : "pending",
      );
    });
    return false;
  };

  const refreshCollection = async () => {
    try {
      const response = await fetch(collectionDialog.dataset.statusUrl, {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (response.ok && renderProgress(await response.json())) return;
    } catch (_) {
      // A transient local refresh failure is retried without changing job state.
    }
    window.setTimeout(refreshCollection, 800);
  };

  closeButton?.addEventListener("click", () => collectionDialog.close());
  finishLink?.addEventListener("click", (event) => {
    event.preventDefault();
    if (collectionDialog.open) collectionDialog.close();
    window.location.replace(finishLink.href);
  });
  if (collectionDialog.dataset.autoOpen === "true" && collectionDialog.showModal) {
    collectionDialog.showModal();
  }
  refreshCollection();
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
    "manual-rdap": "evidence",
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
    if (hashStep === "manual-rdap") {
      const manualRdap = document.getElementById("manual-rdap");
      if (manualRdap) {
        manualRdap.open = true;
        if (focusPanel) manualRdap.scrollIntoView({ behavior: "smooth", block: "start" });
      }
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
