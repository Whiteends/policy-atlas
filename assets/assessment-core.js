export const VALID_STATUSES = new Set(["detected", "missing", "not_applicable", "manual_confirmation", "unknown", "error"]);

export function validateSnapshot(snapshot) {
  const errors = [];
  const required = ["schemaVersion", "scriptVersion", "modelVersion", "policyLibraryVersion", "generatedAt", "tenant", "collector", "context", "assessment", "signals", "manualChecks", "warnings", "errors"];
  for (const property of required) if (!(property in (snapshot ?? {}))) errors.push(`Missing required property: ${property}`);
  if (snapshot?.schemaVersion !== "1.0.0") errors.push(`Unsupported schema version: ${snapshot?.schemaVersion ?? "missing"}`);
  if (!/^[a-f0-9]{64}$/.test(snapshot?.tenant?.fingerprint ?? "")) errors.push("Tenant fingerprint is missing or malformed.");
  if (Number.isNaN(Date.parse(snapshot?.generatedAt ?? ""))) errors.push("generatedAt is not a valid timestamp.");
  for (const [id, signal] of Object.entries(snapshot?.signals ?? {})) {
    if (!VALID_STATUSES.has(signal?.status)) errors.push(`${id}: invalid status.`);
    if (!signal?.reason) errors.push(`${id}: reason is required.`);
    if (!Array.isArray(signal?.evidence)) errors.push(`${id}: evidence must be an array.`);
    if (Number.isNaN(Date.parse(signal?.checkedAt ?? ""))) errors.push(`${id}: checkedAt is invalid.`);
  }
  return errors;
}

export function scoreSignals(signals, model) {
  const stageResults = {};
  let stage = 0;
  let provisionalStage = 0;
  let knownTotal = 0;
  let requiredTotal = 0;
  for (const [stageKey, definition] of Object.entries(model.stages)) {
    const rows = definition.required.map(id => ({ id, status: signals[id]?.status ?? "unknown", critical: definition.critical.includes(id) }));
    const detected = rows.filter(row => row.status === "detected");
    const unresolved = rows.filter(row => ["unknown", "manual_confirmation", "error"].includes(row.status));
    const missing = rows.filter(row => row.status === "missing");
    const applicable = rows.filter(row => row.status !== "not_applicable");
    const failedCritical = rows.filter(row => row.critical && row.status !== "detected");
    const coveragePercent = applicable.length ? Math.round((detected.length / applicable.length) * 100) : 0;
    const confirmed = coveragePercent >= model.stageThresholdPercent && failedCritical.length === 0 && unresolved.length === 0;
    const provisional = coveragePercent >= model.stageThresholdPercent && !failedCritical.some(row => row.status === "missing");
    stageResults[stageKey] = { stage: Number(stageKey), requiredCount: definition.required.length, applicableCount: applicable.length, detectedCount: detected.length, coveragePercent, confirmed, provisional, missing: missing.map(row => row.id), unresolved: unresolved.map(row => row.id), failedCritical: failedCritical.map(row => row.id) };
    knownTotal += rows.filter(row => ["detected", "missing", "not_applicable"].includes(row.status)).length;
    requiredTotal += rows.length;
    if (confirmed && stage === Number(stageKey) - 1) stage = Number(stageKey);
    if (provisional && provisionalStage === Number(stageKey) - 1) provisionalStage = Number(stageKey);
  }
  const weightedRows = Object.entries(model.weightedScoring.weights).map(([id, weight]) => ({ id, weight, status: signals[id]?.status ?? "unknown" }));
  const availablePoints = weightedRows.filter(row => row.status !== "not_applicable").reduce((sum, row) => sum + row.weight, 0);
  const earnedPoints = weightedRows.filter(row => row.status === "detected").reduce((sum, row) => sum + row.weight, 0);
  const unresolvedPoints = weightedRows.filter(row => ["unknown", "manual_confirmation", "error"].includes(row.status)).reduce((sum, row) => sum + row.weight, 0);
  const maturityScore = availablePoints ? Math.round((earnedPoints / availablePoints) * 100) : 0;
  let scoreStage = 0;
  for (const band of [...model.weightedScoring.bands].sort((a, b) => a.minimum - b.minimum)) if (maturityScore >= band.minimum) scoreStage = band.stage;
  let criticalCap = 4;
  for (let stageNumber = 1; stageNumber <= 4; stageNumber += 1) {
    if (model.stages[String(stageNumber)].critical.some(id => signals[id]?.status !== "detected")) { criticalCap = stageNumber - 1; break; }
  }
  stage = scoreStage;
  provisionalStage = stage;
  const confidence = requiredTotal ? Math.round((knownTotal / requiredTotal) * 100) / 100 : 0;
  return { stage, provisionalStage, maturityScore, earnedPoints, availablePoints, unresolvedPoints, scoreStage, criticalCap, confidence, confidenceLabel: confidence >= .85 ? "high" : confidence >= .6 ? "moderate" : "low", stageResults };
}
