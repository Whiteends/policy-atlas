# Conditional Access Maturity & Policy Tool — Build Spec for Codex

## 0. What this system does

A Cloudflare-hosted site (subdomain or path on your existing domain) that:
1. Explains a 5-stage Conditional Access maturity model (Stage 0 Unmanaged → Stage 4 Optimized/Zero Trust) with detail on what each stage looks like, its risks, and how to graduate.
2. Provides a searchable/filterable library of real Conditional Access policy templates, each tagged to the maturity stage it belongs to, with rationale and gotchas.
3. **Flagship feature:** a PowerShell script (provided, see §7) that connects read-only to a visitor's own Entra tenant via Microsoft Graph, detects what's actually configured, and scores their real maturity stage — rather than relying on self-report.
4. A lighter-weight fallback: a client-side interactive quiz for anyone who can't or won't run the script, scored against the same maturity model, giving the same kind of "here's your stage, here's what to add next" output from self-reported answers.

This is a portfolio/demonstration piece — it should read as something built by someone who has actually run CA in production, not a regurgitation of Microsoft docs. The script in particular is the strongest signal of that: a self-report quiz shows you understand the framework, a tool that reads real tenant config and scores it shows you've built the kind of thing a security team would actually use.

**Minimal-effort version (build this first):** fully static site, content driven by two JSON files (already provided), assessment scoring done entirely client-side in JavaScript. No database, no backend API calls needed for v1. Single Cloudflare Worker (or Pages project) serving static HTML/CSS/JS.

---

## 1. Content already provided — do not regenerate

- `ca-maturity-model.json` — the 5 stages, fully written (name, description, characteristics, risks, graduation triggers). Use as-is.
- `ca-policy-library.json` — 14 policy templates, each tagged with `maturity_stage`, `category`, description, conditions, grant controls, rationale, and gotchas. Use as-is.

Both are ready to load directly into the frontend as static JSON — no transformation needed for v1.

**Note for Codex:** a couple of items in the policy library (Global Secure Access licensing/availability, exact CAE token-lifetime figures) are flagged in the JSON as "verify against current Microsoft documentation" — these are areas where Microsoft's feature set moves quickly. Worth a quick check against current Entra docs before publishing, since this is a credibility-sensitive project (it's a CV-adjacent artifact).

---

## 2. Site structure

```
/                     — landing: what the tool is, quick nav to the 3 sections below
/maturity-model        — the 5 stages, one section each, visually distinct (e.g. a horizontal
                          stepper/timeline component), expandable detail per stage
/policy-library         — filterable table/card grid of policies: filter by maturity_stage,
                          category; each policy expands to show full detail + gotchas
/assessment              — the interactive quiz: ~8-12 questions mapped to maturity
                          indicators (see §4), client-side scored, ends with a result page:
                          "You're at Stage N: [name]" + a filtered list of policy-library
                          entries recommended as next steps
```

Single-page app is fine (client-side routing) or plain multi-page static HTML — whichever is less code. Given "minimal effort," plain static HTML with a shared JS file for the assessment logic is probably simpler than a JS framework here.

---

## 3. Design notes

- This is a professional/security-industry audience — treat it like a polished internal tool or vendor microsite, not a marketing landing page. Read the `frontend-design` skill/guidance available in this environment before styling, for tone and typography choices appropriate to a technical/security audience.
- The maturity model should visually communicate progression (a stepper, ladder, or horizontal stage indicator) — this is the single most important visual element on the site.
- Policy library should be scannable — a card or table grid with stage/category badges, not a wall of text.

---

## 4. Assessment logic (client-side JS)

Simple rule-based scoring, no ML/LLM needed:

1. Ask ~8-12 yes/no or multiple-choice questions, each mapped to one or more `characteristics` from the maturity model stages (e.g. "Is Security Defaults still your only MFA control?", "Do you have documented, tested break-glass accounts?", "Is device compliance required for any sensitive apps?", "Do you have Entra ID P2 / Identity Protection enabled and in use?", "Are any policies using authentication strength / phishing-resistant MFA?", "Is Continuous Access Evaluation enabled?").
2. Score: the respondent's stage = the highest stage where they meet most/all of that stage's core characteristics, computed as a simple weighted count — no need for anything more sophisticated.
3. Result page shows: current stage (from `ca-maturity-model.json`), what's missing to reach the next stage (diff the stage's `characteristics` against their answers), and a filtered pull from `ca-policy-library.json` for `maturity_stage == current_stage + 1`.

Keep the question set editable as a small JS/JSON array — Codex should not hardcode question logic deep inside markup, to make future tuning easy.

---

## 5. Build order for Codex

1. Static site skeleton: `/`, `/maturity-model`, `/policy-library`, `/assessment` — plain HTML/CSS, load the two JSON files as static assets, render maturity stages and policy cards from them. Confirm content renders correctly before adding interactivity.
2. Style pass using the design guidance in §3 — confirm it looks credible before adding the assessment logic.
3. Assessment questions + client-side scoring logic (§4) — build and test scoring against a few manual "fake answer" runs to confirm stage assignment feels right before wiring up the UI.
4. Wire assessment UI to scoring logic, build the result page with policy recommendations.
5. Deploy via Cloudflare Pages or a Worker serving static assets, on a subdomain (e.g. `ca.yourdomain.com`) or a path on the existing domain.

**Stop and confirm with me after step 1 and after step 3** before continuing — those are the two steps most likely to need content/logic adjustments before more is built on top.

---

## 6. Optional v2 (do not build yet)

- Shareable assessment results via a short link (would need Cloudflare KV to store result state + a Worker route to resolve share links) — only add this if the static version is well received and you want people to be able to share their score.
- A "policy as code" export — generate a Microsoft Graph API/Terraform snippet for a selected policy from the library, so a visitor could copy real config, not just read about it. This would meaningfully raise the "built by someone who's done this in production" signal, but it's extra build time — worth doing after v1 is live and validated.

---

## 7. Flagship feature: the environment assessment script

The client-side quiz in the assessment page (§4) is a self-report — it measures what
someone *thinks* their tenant looks like. A script that reads the actual tenant
configuration via Microsoft Graph measures what's *actually there*, which is a much
stronger artifact and should be positioned as the primary offering, with the quiz
kept as a fallback for people who can't or won't run an admin script against their
tenant.

**Two files are provided, ready to use, alongside this spec:**
- `Assess-ConditionalAccessMaturity.ps1` — the script itself. Auth, signal
  collection, scoring engine, HTML report generation, and diff mode (comparing two
  runs to show what's improved) are implemented. A handful of checks are marked
  `BEST-EFFORT / VERIFY` in comments where Graph schema has shifted across SDK
  versions — confirm those against current Microsoft Graph documentation before
  treating the script as fully validated.
- `SCRIPT-README.md` — documentation for the script itself: exact permissions
  requested and why, what it does and doesn't do, usage. This should ship alongside
  the script wherever it's published (GitHub, and linked from the website) since an
  admin should be able to review it before granting Graph consent.

### Key design points, don't compromise on these

- **Read-only Graph scopes only, always.** No write/modify scope is ever requested.
  This is enforced by the explicit `$RequiredScopes` list at the top of the script —
  if extending the script, any new signal must be collected via a read scope.
- **No telemetry, no phone-home.** The script writes its report only to the local
  machine it's run from. Nothing is transmitted to your website, your Cloudflare
  Worker, or anywhere else, unless a user explicitly opts in later (see the optional
  upload flow below).
- **Scoring reuses the exact same `ca-maturity-model.json` and `ca-policy-library.json`
  as the website** — one scoring engine, not two divergent ones. The script's signal
  keys (e.g. `block-legacy-auth`, `risk-based-signin`) are the same IDs as the
  policy library entries, so a detected/missing signal maps directly onto a fully
  documented policy with rationale and gotchas.
- **Unverifiable signals are reported as "confirm manually," never guessed at.**
  Governance/process controls (policy-as-code) and features that live outside the
  CA policy object (Global Secure Access, Defender for Cloud Apps session control,
  insider risk integration) fall in this category.

### Integration with the website

1. Publish the script + README on your own GitHub, linked prominently from the
   `/assessment` page as "Run it against your own tenant" — with the client-side
   quiz framed as the lighter-weight alternative for anyone who can't run it.
2. Optional, opt-in only, build after v1 of everything else is live: let a visitor
   paste/upload the JSON snapshot the script produces into the website to render the
   same nicer visual report the quiz produces, using client-side JS only — never a
   server-side upload, since tenant configuration data should not need to leave the
   visitor's machine to get a nicely formatted view of it.
3. Diff mode is already built into the script (`-CompareTo`) — consider surfacing
   "run this again in 3 months to track progress" messaging in the report/README,
   since a tracked-improvement story is a stronger demo than a one-off score.

### Build order addition

Insert after step 2 (styling pass) and before step 3 (quiz logic) in §5's build
order: get the script running end-to-end against a real or test tenant, confirm the
HTML report renders sensibly, and confirm the JSON snapshot format is stable —
**before** building the optional website upload flow against it, since that flow
depends on the snapshot schema being settled first.
