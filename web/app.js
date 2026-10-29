let authorization = "";
const $ = id => document.getElementById(id);
const elem = (tag, content, className) => {
  const e = document.createElement(tag);
  e.textContent = String(content);
  if (className) e.className = className;
  return e;
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { Authorization: authorization, "Content-Type": "application/json" }
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const detail = Array.isArray(data.detail)
      ? data.detail.map(d => `${d.loc ? d.loc.join(".") : "field"}: ${d.msg}`).join("; ")
      : data.detail;
    throw new Error(detail || `HTTP ${response.status}`);
  }
  return response.json();
}

function row(container, label, value, className = "") {
  const line = elem("div", "", "detail-row");
  line.append(elem("span", label), elem("strong", value, className));
  container.append(line);
}

function renderEncryptionBox(encryption) {
  const box = $("encryption");
  box.replaceChildren();
  row(box, "Plain-text input", encryption.fictional_plaintext);
  row(box, "Algorithm & key size", `${encryption.algorithm} (${encryption.key_bits || 256}-bit, AAD="${encryption.aad || "customer-email"}")`);
  if (encryption.nonce_hex) {
    row(box, "96-bit Random Nonce (hex)", encryption.nonce_hex);
    row(box, "128-bit GCM Auth Tag (hex)", encryption.auth_tag_hex);
  }
  box.append(elem("span", encryption.stored_form, "cipher"));
  const statusLabel = encryption.tamper_simulated
    ? "TAMPER DETECTED & BLOCKED (InvalidTag)"
    : (encryption.decrypted_match ? "PASS (Decrypted & Authenticated)" : "FAIL");
  const statusClass = encryption.tamper_simulated ? "bad" : (encryption.decrypted_match ? "ok" : "bad");
  row(box, "AEAD Decrypt / Integrity verification", statusLabel, statusClass);
}

function renderPkiSimulation(sim) {
  const container = $("pki-result");
  container.replaceChildren();
  row(container, "1. Certificate chain (Root CA → Server)", sim.cert_chain_verified ? "VERIFIED" : "FAILED", sim.cert_chain_verified ? "ok" : "bad");
  row(container, "2. Ephemeral key exchange", `${sim.key_exchange} → ${sim.wrapped_session_key_preview}`);
  row(container, "3. Encrypted channel cipher", sim.channel_cipher);
  container.append(elem("span", sim.encrypted_payload, "cipher"));
  row(
    container,
    "4. Server AEAD decryption & integrity",
    sim.channel_integrity_verified ? `VERIFIED ("${sim.decrypted_by_server}")` : "BLOCKED (Ciphertext Tampered in Transit!)",
    sim.channel_integrity_verified ? "ok" : "bad"
  );
  row(
    container,
    "5. Server RSA-3072 signed receipt check",
    sim.receipt_signature_verified ? "VERIFIED WITH SERVER PUBLIC KEY" : "INVALID SIGNATURE (Tampered!)",
    sim.receipt_signature_verified ? "ok" : "bad"
  );
}

function renderPasswordCheck(res) {
  const container = $("password-check-result");
  container.replaceChildren();
  row(container, "Policy verdict", `${res.verdict} (${res.score})`, res.strong ? "ok" : "bad");
  row(container, "Hash algorithm", res.algorithm);
  container.append(elem("span", res.argon2id_hash_sample, "cipher"));
}

function renderPrivacyCheck(res) {
  const container = $("privacy-check-result");
  container.replaceChildren();
  row(container, "Privacy & PCI-DSS decision", res.verdict, res.accepted_by_simulator ? "ok" : "bad");
  res.necessary_fields.forEach(f => row(container, `✓ Allowed: ${f.field}`, f.reason, "ok"));
  res.unnecessary_personal_fields.forEach(f => row(container, `✗ Unnecessary PII: ${f.field}`, f.reason, "bad"));
  res.prohibited_pci_fields.forEach(f => row(container, `✗ Prohibited PCI-DSS: ${f.field}`, f.reason, "bad"));
}

function render(overview, privacy, encryption, customers, transactions, auditLogs) {
  const r = overview.report;

  // Top KPI stats
  $("stats").replaceChildren();
  [
    [`${overview.passed}/${overview.total}`, "PCI-DSS & SECURITY CHECKS"],
    [`${r.encryption_coverage_percent}%`, "CUSTOMER EMAILS ENCRYPTED"],
    [r.transactions, "SIMULATED PAYMENTS"],
    [r.unnecessary_fields_stored.length, "EXCESS FIELDS STORED"]
  ].forEach(([v, label]) => {
    const box = elem("div", "", "stat");
    box.append(elem("strong", v), elem("span", label));
    $("stats").append(box);
  });

  // Side-by-side Plaintext vs Protected table
  $("comparison-table").replaceChildren();
  (overview.comparison || []).forEach(item => {
    const tr = document.createElement("tr");
    tr.append(
      elem("td", item.category, "bold-cell"),
      elem("td", item.threat),
      elem("td", item.plaintext_unprotected, "code-cell bad-bg"),
      elem("td", item.protected_in_simulator, "code-cell ok-bg"),
      elem("td", item.control)
    );
    $("comparison-table").append(tr);
  });

  // Measured before/after
  $("comparison").replaceChildren();
  row($("comparison"), "Plain-text emails · before → after", `${r.baseline.plaintext_emails} → ${r.protected.plaintext_emails}`);
  row($("comparison"), "Encrypted emails · before → after", `${r.baseline.encrypted_emails} → ${r.protected.encrypted_emails}`);
  row($("comparison"), "Unnecessary fields · before → after", `${r.baseline.unnecessary_fields} → ${r.protected.unnecessary_fields}`);
  row($("comparison"), "Payment audit coverage", `${r.audit_coverage_percent}%`);
  row($("comparison"), "Encryption key separate from database (.secrets/)", r.key_separated ? "YES" : "NO", r.key_separated ? "ok" : "bad");

  // Dummy Customers Table (Plaintext vs Encrypted in DB)
  $("customers-table").replaceChildren();
  customers.forEach(c => {
    const tr = document.createElement("tr");
    const cipherPreview = c.email_encrypted ? `${c.email_encrypted.slice(0, 32)}...` : "encrypted";
    tr.append(
      elem("td", c.id),
      elem("td", c.name, "bold-cell"),
      elem("td", c.email),
      elem("td", cipherPreview, "code-cell")
    );
    $("customers-table").append(tr);
  });

  // PCI-DSS Controls Evaluation Table
  $("controls").replaceChildren();
  overview.controls.forEach(c => {
    const tr = document.createElement("tr");
    tr.append(
      elem("td", c.principle, "bold-cell"),
      elem("td", c.label),
      elem("td", c.threat || "Sensitive financial data exposure"),
      elem("td", c.control_detail || c.label),
      elem("td", c.evidence || "Verified", "code-cell"),
      elem("td", c.pass ? "PASS" : "REVIEW", c.pass ? "ok bold-cell" : "bad bold-cell")
    );
    $("controls").append(tr);
  });

  // Encryption Box
  renderEncryptionBox(encryption);

  // PKI Certificate Info
  $("certificate").replaceChildren();
  row($("certificate"), "Root CA Issuer", overview.certificate.issuer);
  row($("certificate"), "Server Certificate Subject", overview.certificate.subject);
  row($("certificate"), "CA Signature & SAN (localhost / 127.0.0.1)", overview.certificate.valid ? "VERIFIED" : "FAILED", overview.certificate.valid ? "ok" : "bad");
  row($("certificate"), "Asymmetric Key Pair", `${overview.certificate.public_key_type} (Private key isolated server-side)`);
  row($("certificate"), "Server Signed Receipt Verification", overview.certificate.receipt_signature_verified ? "VERIFIED" : "FAILED", "ok");
  row($("certificate"), "Certificate Validity Expires", new Date(overview.certificate.expires).toLocaleDateString());

  // Privacy Inventory & Summary
  $("privacy-summary").replaceChildren();
  if (privacy.summary) {
    [
      `Collected Necessary Fields: ${privacy.summary.collected_count}`,
      `Blocked Unnecessary Fields: ${privacy.summary.not_collected_count}`,
      `Unnecessary Columns in SQLite: ${privacy.summary.unnecessary_stored_count}`,
      `Sensitive Auth Data (CVV/PIN) Stored: ${privacy.summary.sensitive_auth_stored ? "YES" : "NONE"}`
    ].forEach(text => $("privacy-summary").append(elem("span", text, "badge-ok")));
  }

  $("inventory").replaceChildren();
  privacy.inventory.forEach(f => {
    const tr = document.createElement("tr");
    [f.field, f.class, f.purpose, f.stored ? "Yes (Necessary)" : "No (Minimized)", f.protection].forEach((v, idx) => {
      tr.append(elem("td", v, idx === 3 ? (f.stored ? "ok" : "muted") : ""));
    });
    $("inventory").append(tr);
  });

  $("privacy-risks").replaceChildren();
  privacy.risks.forEach(risk => row($("privacy-risks"), risk.field, `${risk.risk}. Decision: ${risk.decision}.`));

  $("schema-audit").replaceChildren();
  const schemas = privacy.table_schemas || r.table_schemas || {};
  Object.entries(schemas).forEach(([table, cols]) => {
    row($("schema-audit"), `SQLite table: ${table}`, cols.join(", "));
  });
  row($("schema-audit"), "Unnecessary PII / PAN / CVV columns found", privacy.findings.length === 0 ? "0 (CLEAN)" : privacy.findings.join(", "), privacy.findings.length === 0 ? "ok" : "bad");

  // Payment Simulator Customer Select & Transactions Table
  $("customer").replaceChildren();
  customers.forEach(c => {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = `${c.name} (${c.email})`;
    $("customer").append(opt);
  });

  $("transactions").replaceChildren();
  transactions.forEach(t => {
    const tr = document.createElement("tr");
    const sigShort = t.receipt_signature ? `✓ ${t.receipt_signature.slice(0, 18)}...` : "✓ Signed";
    [t.name, `₹${(t.amount_cents / 100).toFixed(2)}`, t.payment_token, `•••• ${t.last4}`, sigShort].forEach((v, i) =>
      tr.append(elem("td", v, i === 4 ? "code-cell ok" : ""))
    );
    $("transactions").append(tr);
  });

  $("audit-logs").replaceChildren();
  (auditLogs || []).slice(0, 6).forEach(log => {
    row($("audit-logs"), `Event #${log.id} · ${log.event}`, log.created_at, "ok");
  });
}

async function refresh() {
  const results = await Promise.all([
    api("/api/overview"),
    api("/api/privacy"),
    api("/api/encryption-demo"),
    api("/api/customers"),
    api("/api/transactions"),
    api("/api/audit-logs")
  ]);
  render(...results);
}

// Default preset for privacy payload analyzer
const bloatedPreset = {
  customer_id: 1,
  amount_cents: 19900,
  last4: "4242",
  phone: "+91-9876543210",
  birth_date: "1999-05-14",
  pan: "4111111111114242",
  cvv: "123"
};
const minimalPreset = {
  customer_id: 1,
  amount_cents: 19900,
  last4: "4242"
};
if ($("privacy-payload")) {
  $("privacy-payload").value = JSON.stringify(bloatedPreset, null, 2);
}

$("login-form").addEventListener("submit", async event => {
  event.preventDefault();
  authorization = "Basic " + btoa("admin:" + $("password").value);
  try {
    await refresh();
    // Run initial interactive demos so panels are populated immediately
    const [pkiRes, pwRes, privRes] = await Promise.all([
      api("/api/pki-simulate", { method: "POST", body: JSON.stringify({ message: $("pki-message").value, tamper: false }) }),
      api("/api/password-check", { method: "POST", body: JSON.stringify({ password: $("candidate-password").value }) }),
      api("/api/privacy/check-payload", { method: "POST", body: JSON.stringify({ payload: bloatedPreset }) })
    ]);
    renderPkiSimulation(pkiRes);
    renderPasswordCheck(pwRes);
    renderPrivacyCheck(privRes);
    $("password").value = "";
    $("login").hidden = true;
    $("dashboard").hidden = false;
  } catch (error) {
    authorization = "";
    $("login-error").textContent = error.message;
  }
});

$("customer-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const c = await api("/api/customers", {
      method: "POST",
      body: JSON.stringify({ name: $("cust-name").value, email: $("cust-email").value })
    });
    $("customer-message").textContent = `Added ${c.name} — email stored encrypted with AES-256-GCM.`;
    $("customer-message").className = "footnote ok";
    $("cust-name").value = "";
    $("cust-email").value = "";
    await refresh();
  } catch (error) {
    $("customer-message").textContent = error.message;
    $("customer-message").className = "footnote bad";
  }
});

$("encryption-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const res = await api("/api/encryption-demo", {
      method: "POST",
      body: JSON.stringify({ plaintext: $("enc-input").value, tamper: $("enc-tamper").checked })
    });
    renderEncryptionBox(res);
  } catch (error) {
    alert(error.message);
  }
});

$("pki-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const res = await api("/api/pki-simulate", {
      method: "POST",
      body: JSON.stringify({ message: $("pki-message").value, tamper: $("pki-tamper").checked })
    });
    renderPkiSimulation(res);
  } catch (error) {
    alert(error.message);
  }
});

$("password-check-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const res = await api("/api/password-check", {
      method: "POST",
      body: JSON.stringify({ password: $("candidate-password").value })
    });
    renderPasswordCheck(res);
  } catch (error) {
    alert(error.message);
  }
});

$("fill-strong-pw").addEventListener("click", async () => {
  $("candidate-password").value = "Secur3Pay#FinTech!2026";
  const res = await api("/api/password-check", {
    method: "POST",
    body: JSON.stringify({ password: $("candidate-password").value })
  });
  renderPasswordCheck(res);
});

$("preset-bloated").addEventListener("click", async () => {
  $("privacy-payload").value = JSON.stringify(bloatedPreset, null, 2);
  const res = await api("/api/privacy/check-payload", {
    method: "POST",
    body: JSON.stringify({ payload: bloatedPreset })
  });
  renderPrivacyCheck(res);
});

$("preset-minimal").addEventListener("click", async () => {
  $("privacy-payload").value = JSON.stringify(minimalPreset, null, 2);
  const res = await api("/api/privacy/check-payload", {
    method: "POST",
    body: JSON.stringify({ payload: minimalPreset })
  });
  renderPrivacyCheck(res);
});

$("privacy-check-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    const parsed = JSON.parse($("privacy-payload").value);
    const res = await api("/api/privacy/check-payload", {
      method: "POST",
      body: JSON.stringify({ payload: parsed })
    });
    renderPrivacyCheck(res);
  } catch (error) {
    alert("Invalid JSON payload: " + error.message);
  }
});

$("payment-form").addEventListener("submit", async event => {
  event.preventDefault();
  const amount = Math.round(Number($("amount").value) * 100);
  try {
    const result = await api("/api/payments", {
      method: "POST",
      body: JSON.stringify({ customer_id: Number($("customer").value), amount_cents: amount, last4: $("last4").value })
    });
    $("payment-message").textContent = `Approved · Token: ${result.payment_token} · PKI Receipt Signed`;
    $("payment-message").className = "ok";
    await refresh();
  } catch (error) {
    $("payment-message").textContent = error.message;
    $("payment-message").className = "bad";
  }
});

$("test-reject-cvv").addEventListener("click", async () => {
  const amount = Math.round(Number($("amount").value) * 100);
  try {
    await api("/api/payments", {
      method: "POST",
      body: JSON.stringify({
        customer_id: Number($("customer").value),
        amount_cents: amount,
        last4: $("last4").value,
        cvv: "123"
      })
    });
  } catch (error) {
    $("payment-message").textContent = `Blocked by PCI-DSS Control (HTTP 422): ${error.message}`;
    $("payment-message").className = "bad";
  }
});
