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
    copyButton.textContent = "Copied";
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
