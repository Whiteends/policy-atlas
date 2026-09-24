import { scoreSignals, validateSnapshot } from "/assets/assessment-core.js";

const input = document.querySelector("[data-snapshot-input]");
const drop = document.querySelector("[data-snapshot-drop]");
const output = document.querySelector("[data-report-output]");
const clear = document.querySelector("[data-clear-report]");
const escapeHtml = value => String(value ?? "").replace(/[&<>'"]/g, character => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[character]);

function sameScore(left, right) {
  if (right.maturityScore === undefined) return left.stage === right.stage && left.provisionalStage === right.provisionalStage && left.confidence === right.confidence;
  return left.stage === right.stage && left.maturityScore === right.maturityScore && left.earnedPoints === right.earnedPoints && left.availablePoints === right.availablePoints;
}

function render(snapshot, score, stages, policies) {
  const stage = stages.find(item => item.id === score.stage);
  const next = stages.find(item => item.id === score.stage + 1);
  const statuses = Object.values(snapshot.signals).reduce((counts, signal) => ({...counts, [signal.status]:(counts[signal.status] ?? 0) + 1}), {});
  const missingIds = next ? score.stageResults[String(next.id)]?.missing ?? [] : [];
  const recommendations = policies.filter(policy => missingIds.includes(policy.id));
  const rows = Object.entries(snapshot.signals).map(([id, signal]) => `<tr><td><code>${escapeHtml(id)}</code></td><td><span class="signal-status signal-${escapeHtml(signal.status)}">${escapeHtml(signal.status.replaceAll("_", " "))}</span></td><td>${escapeHtml(signal.reason)}</td><td>${signal.evidence.length}</td></tr>`).join("");
  output.innerHTML = `<section class="report-summary"><div><p class="kicker">Assessed maturity</p><strong>${score.stage}</strong><h2>${escapeHtml(stage?.name ?? "Unmanaged")}</h2></div><dl><div><dt>Weighted score</dt><dd>${score.maturityScore}/100</dd></div><div><dt>Points earned</dt><dd>${score.earnedPoints} of ${score.availablePoints}</dd></div><div><dt>Detected</dt><dd>${statuses.detected ?? 0}</dd></div><div><dt>Manual checks</dt><dd>${statuses.manual_confirmation ?? 0}</dd></div><div><dt>Generated</dt><dd>${escapeHtml(new Date(snapshot.generatedAt).toLocaleString())}</dd></div></dl></section>
  <section class="section"><div class="section-head"><h2>Signal findings</h2><small>${Object.keys(snapshot.signals).length} ASSESSED SIGNALS</small></div><div class="table-scroll"><table class="permission-table"><thead><tr><th>Signal</th><th>Status</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table></div></section>
  <section class="section"><div class="section-head"><h2>${next ? `Gaps toward Stage ${next.id}` : "Maintenance priorities"}</h2><small>${recommendations.length} POLICY PATTERNS</small></div>${recommendations.length ? `<div class="recommendation-list">${recommendations.map(policy => `<a href="/policy-library/#${escapeHtml(policy.id)}"><span>Stage ${policy.maturity_stage} · ${escapeHtml(policy.category)}</span><strong>${escapeHtml(policy.name)}</strong><p>${escapeHtml(policy.description)}</p></a>`).join("")}</div>` : `<div class="empty">No missing policy patterns were identified for the next stage.</div>`}</section>`;
}

async function handleFile(file) {
  output.innerHTML = `<div class="empty">Validating snapshot locally…</div>`;
  try {
    if (file.size > 5 * 1024 * 1024) throw new Error("Snapshot exceeds the 5 MB local safety limit.");
    const snapshot = JSON.parse(await file.text());
    const errors = validateSnapshot(snapshot);
    if (errors.length) throw new Error(errors.join(" "));
    const [model, maturity, library] = await Promise.all([
      fetch("/assessment-model.json").then(response => response.json()),
      fetch("/ca-maturity-model.json").then(response => response.json()),
      fetch("/ca-policy-library.json").then(response => response.json())
    ]);
    if (snapshot.modelVersion !== model.version) throw new Error(`Snapshot model ${snapshot.modelVersion} is incompatible with website model ${model.version}.`);
    const score = scoreSignals(snapshot.signals, model);
    if (!sameScore(score, snapshot.assessment)) throw new Error("Stored maturity score does not match a fresh browser calculation. The snapshot may be corrupted or incompatible.");
    render(snapshot, score, maturity.stages, library.policies);
    clear.hidden = false;
  } catch (error) {
    output.innerHTML = `<div class="notice"><strong>Snapshot rejected.</strong> ${escapeHtml(error.message)}</div>`;
  }
}

input.addEventListener("change", () => input.files[0] && handleFile(input.files[0]));
drop.addEventListener("dragover", event => { event.preventDefault(); drop.classList.add("is-dragging"); });
drop.addEventListener("dragleave", () => drop.classList.remove("is-dragging"));
drop.addEventListener("drop", event => { event.preventDefault(); drop.classList.remove("is-dragging"); if (event.dataTransfer.files[0]) handleFile(event.dataTransfer.files[0]); });
clear.addEventListener("click", () => { input.value = ""; output.innerHTML = ""; clear.hidden = true; });
