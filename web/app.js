let authorization = "";
const $ = id => document.getElementById(id);
const elem = (tag, content, className) => { const e = document.createElement(tag); e.textContent = String(content); if (className) e.className = className; return e; };
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {Authorization: authorization, "Content-Type": "application/json"}});
  if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.detail || `HTTP ${response.status}`); }
  return response.json();
}
function row(container, label, value, className = "") {
  const line = elem("div", "", "detail-row"); line.append(elem("span", label), elem("strong", value, className)); container.append(line);
}
function render(overview, privacy, encryption, customers, transactions) {
  const r = overview.report;
  $("stats").replaceChildren();
  [[`${overview.passed}/${overview.total}`, "SECURITY CHECKS"], [`${r.encryption_coverage_percent}%`, "EMAILS ENCRYPTED"], [r.transactions, "SIMULATED PAYMENTS"], [r.unnecessary_fields_stored.length, "EXCESS FIELDS"]].forEach(([v, label]) => {
    const box = elem("div", "", "stat"); box.append(elem("strong", v), elem("span", label)); $("stats").append(box);
  });
  $("comparison").replaceChildren();
  row($("comparison"), "Plaintext emails · before → after", `${r.baseline.plaintext_emails} → ${r.protected.plaintext_emails}`);
  row($("comparison"), "Encrypted emails · before → after", `${r.baseline.encrypted_emails} → ${r.protected.encrypted_emails}`);
  row($("comparison"), "Unnecessary fields · before → after", `${r.baseline.unnecessary_fields} → ${r.protected.unnecessary_fields}`);
  row($("comparison"), "Payment audit coverage", `${r.audit_coverage_percent}%`);
  row($("comparison"), "Encryption key separate from database", r.key_separated ? "YES" : "NO", r.key_separated ? "ok" : "bad");
  $("controls").replaceChildren();
  overview.controls.forEach(c => { const line = elem("div", "", "control-row"); line.append(elem("span", `${c.principle}: ${c.label}`), elem("strong", c.pass ? "PASS" : "REVIEW", c.pass ? "ok" : "bad")); $("controls").append(line); });
  $("encryption").replaceChildren();
  row($("encryption"), "Fictional plaintext", encryption.fictional_plaintext);
  $("encryption").append(elem("span", encryption.stored_form, "cipher"));
  row($("encryption"), "Decrypt / integrity check", encryption.decrypted_match ? "PASS" : "FAIL", encryption.decrypted_match ? "ok" : "bad");
  $("certificate").replaceChildren();
  row($("certificate"), "Certificate issuer", overview.certificate.issuer);
  row($("certificate"), "Signature and hostname", overview.certificate.valid ? "VERIFIED" : "FAILED", overview.certificate.valid ? "ok" : "bad");
  row($("certificate"), "Public key", overview.certificate.public_key_type);
  row($("certificate"), "Signed receipt check", overview.certificate.receipt_signature_verified ? "VERIFIED" : "FAILED", "ok");
  row($("certificate"), "Expires", new Date(overview.certificate.expires).toLocaleDateString());
  $("inventory").replaceChildren();
  privacy.inventory.forEach(f => { const tr = document.createElement("tr"); [f.field, f.class, f.purpose, f.stored ? "Yes" : "No", f.protection].forEach(v => tr.append(elem("td", v))); $("inventory").append(tr); });
  $("privacy-risks").replaceChildren();
  privacy.risks.forEach(risk => row($("privacy-risks"), risk.field, `${risk.risk}. Decision: ${risk.decision}.`));
  $("customer").replaceChildren();
  customers.forEach(c => { const opt = document.createElement("option"); opt.value = c.id; opt.textContent = c.name; $("customer").append(opt); });
  $("transactions").replaceChildren();
  transactions.forEach(t => { const tr = document.createElement("tr"); [t.name, `₹${(t.amount_cents / 100).toFixed(2)}`, t.payment_token, `•••• ${t.last4}`].forEach(v => tr.append(elem("td", v))); $("transactions").append(tr); });
}
async function refresh() {
  const results = await Promise.all([api("/api/overview"), api("/api/privacy"), api("/api/encryption-demo"), api("/api/customers"), api("/api/transactions")]);
  render(...results);
}
$("login-form").addEventListener("submit", async event => {
  event.preventDefault(); authorization = "Basic " + btoa("admin:" + $("password").value);
  try { await refresh(); $("password").value = ""; $("login").hidden = true; $("dashboard").hidden = false; }
  catch (error) { authorization = ""; $("login-error").textContent = error.message; }
});
$("payment-form").addEventListener("submit", async event => {
  event.preventDefault();
  const amount = Math.round(Number($("amount").value) * 100);
  try {
    const result = await api("/api/payments", {method: "POST", body: JSON.stringify({customer_id: Number($("customer").value), amount_cents: amount, last4: $("last4").value})});
    $("payment-message").textContent = `Approved · ${result.payment_token}`;
    await refresh();
  } catch (error) { $("payment-message").textContent = error.message; }
});
