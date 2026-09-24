const STAGE_COLORS = ["#71808b", "#67b7dc", "#6ee7c2", "#d8df6f", "#f3ca67"];

async function loadJson(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Could not load ${path} (${response.status})`);
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[character]);
}

function list(items) {
  return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderStage(stage) {
  return `<article class="stage-card" id="stage-${stage.id}" style="--stage-color:${STAGE_COLORS[stage.id]}">
    <div class="stage-heading"><h2>Stage ${stage.id}: ${escapeHtml(stage.name)}</h2><span class="stage-number">0${stage.id} / 04</span></div>
    <p class="stage-summary">${escapeHtml(stage.short_description)}</p>
    <div class="detail-grid">
      <section><h3>Typical tenant</h3><p>${escapeHtml(stage.typical_tenant)}</p></section>
      <section><h3>Characteristics</h3>${list(stage.characteristics)}</section>
      <section><h3>Risks of staying here</h3>${list(stage.risks_of_staying_here)}</section>
      <section><h3>Graduation path</h3><p>${escapeHtml(stage.graduation_trigger)}</p><p><strong>Indicative effort:</strong> ${escapeHtml(stage.estimated_effort_to_next_stage ?? "Maintenance stage")}</p></section>
    </div>
  </article>`;
}

async function initMaturityModel() {
  const target = document.querySelector("[data-stage-list]");
  if (!target) return;
  try {
    const { stages } = await loadJson("/ca-maturity-model.json");
    target.innerHTML = stages.map(renderStage).join("");
  } catch (error) { target.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`; }
}

function renderPolicy(policy) {
  return `<details class="policy-card" id="${escapeHtml(policy.id)}">
    <summary>
      <div class="badges"><span class="badge">Stage ${policy.maturity_stage}</span><span class="badge">${escapeHtml(policy.category)}</span></div>
      <h3>${escapeHtml(policy.name)}</h3><p>${escapeHtml(policy.description)}</p>
    </summary>
    <dl class="policy-body">
      <dt>Conditions</dt><dd>${escapeHtml(policy.conditions)}</dd>
      <dt>Grant controls</dt><dd>${escapeHtml(policy.grant_controls)}</dd>
      <dt>Why it matters</dt><dd>${escapeHtml(policy.why_it_matters)}</dd>
      <dt>Implementation gotchas</dt><dd>${list(policy.gotchas)}</dd>
    </dl>
  </details>`;
}

async function initPolicyLibrary() {
  const target = document.querySelector("[data-policy-list]");
  if (!target) return;
  try {
    const { policies } = await loadJson("/ca-policy-library.json");
    const stage = document.querySelector("[data-stage-filter]");
    const category = document.querySelector("[data-category-filter]");
    const search = document.querySelector("[data-policy-search]");
    [...new Set(policies.map(policy => policy.category))].sort().forEach(value => category.add(new Option(value, value)));
    const render = () => {
      const query = search.value.trim().toLowerCase();
      const filtered = policies.filter(policy =>
        (!stage.value || String(policy.maturity_stage) === stage.value) &&
        (!category.value || policy.category === category.value) &&
        (!query || [policy.name, policy.description, policy.category, policy.conditions, policy.grant_controls].join(" ").toLowerCase().includes(query))
      );
      target.innerHTML = filtered.length ? filtered.map(renderPolicy).join("") : `<div class="empty">No policies match these filters.</div>`;
      document.querySelector("[data-policy-count]").textContent = `${filtered.length} of ${policies.length} policies`;
    };
    [stage, category, search].forEach(control => control.addEventListener("input", render));
    render();
  } catch (error) { target.innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`; }
}

initMaturityModel();
initPolicyLibrary();
