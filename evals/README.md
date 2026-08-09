# SRE Agent — RCA Evaluation Harness

A **manual** (not-CI) harness that drives the SRE investigation agent headlessly
over labeled incident cases and scores **root-cause localization** plus a
**reason match**. It lives in `src/bin/sre_evals.rs` (+ `src/bin/rca_convert.rs`)
and is built as the `sre_evals` binary.

> This is a manual evaluation tool. It needs a **live ClickHouse** (populated
> with telemetry) and an **`OPENAI_API_KEY`** — it is deliberately *not* wired into
> CI. Building it (`cargo build`) requires neither.

---

## What it measures

For each case the harness:

1. Builds the same system prompt + user turn the production HTTP handler builds
   (`system_prompt` + `question_context`), appending the incident time/window so
   the agent's `around`-aware tools center correctly.
2. Runs the real agent loop (`loop_runner::run_with_config_and_budget`) with the
   full built-in tool registry against your ClickHouse.
3. Captures the agent's **final report** text.
4. Scores it:
   - **Localization (AC@k)** — extracts a *ranked* list of candidate root-cause
     services from the report by parsing (a) the `## Root Cause` section and
     (b) the **HYPOTHESIS LEDGER** table (ranked by Confidence, preferring
     `supported`, demoting `refuted`). `AC@1` = ground-truth service (or any
     `related` service) is the #1 candidate; `AC@3` = it's in the top 3.
   - **Reason match** — one conservative LLM-judge call returning strict JSON
     `{"match": bool, "why": "..."}` comparing the agent's stated cause to the
     labeled `reason`.
   - Best-effort tool-call count and prompt/completion token usage.

Output: `evals/out/<run-id>.json` (per-case detail) and `<run-id>.md` (aggregate
summary, also printed to stdout): AC@1, AC@3, reason accuracy, case count, avg
tool calls.

---

## Running

```bash
# from the sre-agent crate root
export OPENAI_API_KEY=sk-...       # required (agent + judge)
export OPENAI_BASE_URL=https://... # optional, default https://api.openai.com
export CLICKHOUSE_URL=http://localhost:8123
export CLICKHOUSE_DATABASE=observability
# export CLICKHOUSE_USER / CLICKHOUSE_PASSWORD / QUERY_API_URL as for the server

cargo run --bin sre_evals -- run --cases evals/cases.yaml --out evals/out
cargo run --bin sre_evals -- run --limit 1            # smoke test a single case
```

Flags: `--cases <file>` (default `evals/cases.yaml`), `--limit <N>`,
`--out <dir>` (default `evals/out`). The run id defaults to a UTC timestamp;
override with `SRE_EVALS_RUN_ID`.

## PR6 deterministic replay and release gate

`evals/replay_cases.yaml` is a deterministic, offline suite of 20 labeled
cases covering service silence/down, CPU and memory pressure, database and
dependency latency, traffic surge/skew, deploy/configuration regressions,
queue/disk/network saturation, missing logs, partial traces, contradictory
signals, ambiguous onset, and model/tool failures. Each case stores its
question, expected culprit/mechanism/path, evidence classes, corroboration
minimum, expected report kind, and replayed tool results with tenant and
provenance metadata.

Run it without ClickHouse, credentials, or an LLM:

```bash
SRE_EVALS_RUN_ID=pr6-local cargo run --bin sre_evals -- replay \
  --cases evals/replay_cases.yaml --out evals/out
```

This writes an aggregate JSON/Markdown report and one complete replay artifact
per case under `evals/out/artifacts/<run-id>/`. Artifacts contain the original
question, expected contract, captured report, tool arguments/results,
structured provenance, and prompt/completion/wall-time measurements.

Compare a run to the checked-in baseline:

```bash
cargo run --bin sre_evals -- compare \
  --current evals/out/pr6-local.json \
  --baseline evals/baseline-pr6.json
cargo run --bin sre_evals -- release-gate \
  --current evals/out/pr6-local.json \
  --baseline evals/baseline-pr6.json
```

The release gate currently requires at least 20 cases, AC@1 ≥ 90%, mechanism
accuracy ≥ 85%, false-final rate ≤ 2%, median actual tool calls ≤ 12, and zero
tenant-scope or provenance failures. It also rejects material regressions
against the supplied baseline. The suite reports AC@1/AC@3, mechanism and
causal-chain completeness, confidence Brier score, preliminary usefulness,
actual calls, tokens, wall time, false-final rate, and scope/provenance errors.

---

## Case schema

```yaml
cases:
  - id: my-incident-01            # unique, stable
    description: optional human note
    source: curated               # curated | seeded | benchmark
    input:
      kind: question               # question | anomaly (text is the prompt)
      text: "Free-form incident description / question for the agent."
      around: "2026-06-18T14:30:00Z"   # optional RFC3339 — incident center
    window:                        # optional — narrows the investigation
      start: "2026-06-18T14:20:00Z"
      end:   "2026-06-18T15:00:00Z"
    ground_truth:
      root_cause_service: payments       # the service to localize
      reason: "Bad payments deploy raised the 500 rate at the deploy time."
      related: [gateway]                 # adjacent services that also count as correct
```

The three ground-truth sources (A curated, B seeded, C benchmark) all reduce to
this one schema.

---

## A — Authoring real labeled cases (`source: curated`)

The highest-signal cases. Use a **real, resolved incident** for which you know
the true root cause from the postmortem.

What makes a good curated case:

- **A real incident window with telemetry still in ClickHouse.** The agent can
  only find what's queryable; set `around`/`window` to the actual onset so the
  retention window covers it.
- **A single, specific `root_cause_service`** that the postmortem confirms — not
  a symptom service. If a downstream dependency was truly at fault, that's the
  root cause; list the symptom-bearing service under `related`.
- **A `reason` that names the mechanism**, not just the service: "bad config push
  to `payments` disabled retries, raising 5xx" beats "payments broke". The judge
  is conservative and rewards mechanism-level matches.
- **`related` for genuinely adjacent services** in a cascade, so the agent isn't
  penalized for naming an equally-valid hop.
- **A `text` that reads like the alert/page an on-caller would actually get** —
  symptom-first, not leading the agent to the answer.

Author 5–15 of these spanning your common failure modes (deploy regression,
dependency failure, traffic shift, resource exhaustion, config change). Track the
scores over time as you change prompts/tools.

---

## B — Seeding synthetic faults (`source: seeded`)

When you lack curated incidents, **inject a known fault** into the local docker
stack, note the window, and label the cause. Below are concrete, **non-destructive**
injection recipes for the demo stack (services: `articles`, `gateway`, `media`,
`notifications`, `payments`, `users`).

> This harness does **not** script fault injection (that would be destructive and
> environment-specific). Run these by hand, record the window, then write the case.

1. **Bad deploy marker / version bump (deploy regression).**
   Roll a service to a deliberately broken image tag (or flip a feature flag that
   raises its error rate). Note the deploy timestamp. The agent should correlate
   the error-rate jump with the deploy via `list_deploys`.
   - `ground_truth.root_cause_service`: the deployed service; `reason`: "deploy
     of <svc> at <ts> introduced a regression raising 5xx".

2. **Scale a dependency to zero (dependency failure / starvation).**
   `kubectl scale deploy/<dependency> --replicas=0` (or `docker compose stop
   <dependency>`). Calls into it fail or time out; the symptom shows on the
   *caller*. Note the start time, then `--replicas=1` to restore.
   - `root_cause_service`: the scaled-down dependency; `related`: the caller.

3. **Inject latency on a dependency (latency degradation).**
   Add artificial delay to one service (e.g. a `tc qdisc add ... netem delay
   300ms` on its container, or a built-in latency/chaos toggle). The caller's p99
   inflates while the dependency is the real cause.
   - `root_cause_service`: the delayed service; `related`: the caller.

4. **Throughput starvation (traffic shift).**
   Stop the upstream traffic source (pause the load generator for one service, or
   scale the producer to 0). Downstream throughput drops with *no* errors — tests
   whether the agent checks upstream instead of concluding "the quiet service is
   broken".
   - `root_cause_service`: the upstream/producer; `related`: the starved consumer.

For each: record `around` (onset) and a `window` bounding the fault, **revert the
fault**, and write the case with the cause you injected. Don't claim a case
passed until you've actually run it.

---

## C — Public-benchmark adapter (RCAEval / OpenRCA)

The converter turns a benchmark's **label file** into our `cases.yaml`:

```bash
cargo run --bin sre_evals -- convert-rcaeval path/to/rcaeval_labels.csv   > evals/rcaeval.yaml
cargo run --bin sre_evals -- convert-openrca path/to/openrca_labels.json  > evals/openrca.yaml
```

Accepted shapes (documented in `src/bin/rca_convert.rs`):

- **RCAEval** — per fault case, a `(service[, resource], fault_type[, inject_time])`
  label, as either a CSV manifest or a JSON array. We map `service →
  root_cause_service` and synthesize `reason` from the fault type (+ resource).
- **OpenRCA** — per failure, `{datetime, component, reason}` (JSON array or CSV).
  We map `component → root_cause_service`, carry `reason` through, and convert
  `datetime` (UTC `YYYY-MM-DD HH:MM:SS`) to RFC3339 `around`.

### ⚠️ Telemetry ingestion is NOT implemented (deferred)

The converter handles **labels only**. The benchmarks ship their own telemetry,
which the agent cannot query until it is loaded into the `observability.*`
ClickHouse tables — and **that ingestion step is not implemented here**.
Converted `benchmark` cases are therefore **not runnable** until you load the
matching telemetry separately.

Documented mapping for whoever implements ingestion later (their data → ours):

| Benchmark signal                    | Our ClickHouse target              |
|-------------------------------------|------------------------------------|
| KPI / metric time series            | `observability.metrics_*` tables   |
| Distributed traces (spans)          | `observability.spans`              |
| Service / container logs            | `observability.logs`               |

Each requires aligning their timestamps, `service`/`component` names, and metric
names to our schema (and respecting `tenant_id` if row policies are enforced).
Until that exists, use sources A and B for runnable evaluation.

---

## Notes

- The harness only reads the crate's public APIs; it does not modify the agent's
  production code or prompts.
- Per-case errors (e.g. an LLM timeout) are recorded as a zero-score case with an
  `error` field rather than aborting the whole run.
- Scoring logic (`extract_candidates`, ledger ranking, AC@k, judge-JSON parsing)
  has unit tests that need no network or DB: `cargo test --bin sre_evals`.
