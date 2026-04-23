export {};

const scanForm = document.getElementById('scan-form') as HTMLFormElement;

scanForm.addEventListener('submit', async (e: Event) => {
  e.preventDefault();
  const btn = scanForm.querySelector('[type=submit]') as HTMLButtonElement;
  btn.textContent = 'Starting scan\u2026';
  btn.disabled = true;

  const formData = new FormData(scanForm);
  const res = await fetch('/start-scan', { method: 'POST', body: formData });
  const { scan_id } = await res.json();
  window.location.href = '/scan/' + scan_id;
});
