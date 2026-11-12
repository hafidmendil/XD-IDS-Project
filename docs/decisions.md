# Decision log

## ADR 1 — Default capture-side and working labels for madatasets

### Context
The repository contains a collection of PCAP files under `madatasets/`, but it does not document the original network topology or the exact attacker definitions. The capture registry needs `device_side` and `label` fields for downstream preprocessing and splits.

### Decision
- `device_side` is set to `orig` for every retained capture because no topology evidence supports `resp` and this is the safest default for a working research corpus.
- Labels are assigned from file names using conservative heuristics: `normal*` => `0`, otherwise attack-like names => `1`.
- Duplicate PCAPs are excluded from the canonical registry only on exact SHA-256 equality; similar size/time ranges alone are not treated as proof of duplication.

### Consequences
- This is a scientifically cautious working assumption, not a claim of ground-truth label validity.
- The pipeline remains reproducible and auditable, but any final benchmark must be revalidated once the original dataset provenance and ground-truth labels are confirmed.
- The generated registry is appropriate for local preprocessing, not for publication-quality performance claims.

## ADR 2 — Dataset source access and admissibility

### Context
The research plan names MQTT-IoTIDS2020, Bot-IoT, ToN_IoT, CICIoT2023,
CIC-IDS2017 and madatasets. For most sources, the repository does not include
PCAP files, an exact downloadable file URL, a verified checksum, licence text
or a label-to-PCAP manifest.

### Decision
- Store the stated source pages and known descriptive facts in
  `configs/datasets.yaml`; mark unverified values `NON DISPONIBLE`.
- Do not infer direct download URLs from landing pages. `fetch_datasets.py`
  downloads only HTTP(S) file URLs explicitly registered with an expected
  SHA-256; all currently unverified sources receive manual instructions.
- No dataset is currently E3-admissible until local PCAPs, provenance,
  licensing, topology and reliable labels have been checked.

### Consequences
- The fetch command currently downloads zero datasets. This is an explicit
  access/checksum limitation, not a successful data acquisition.
- E3 has zero currently admissible domains; three future verified domains
  would permit six directed transfers and three leave-one-domain-out tests.

## ADR 3 — PCAP deduplication and window near-duplicate tolerance

### Context
Equal PCAP byte sizes were observed among several filenames, but equal size
does not establish packet-content identity. The preprocessing pipeline also
requires an absolute L-infinity tolerance for numeric window-vector
near-duplicates.

### Decision
- Exclude PCAPs from the canonical capture registry only when SHA-256 hashes
  match exactly. Record every audited source file and its canonical duplicate
  target; do not call a same-size/time-range match a confirmed duplicate.
- Keep the existing preprocessing tolerance at `0.01` absolute L-infinity as
  an operational pipeline setting. It was not independently preregistered
  before the first local experiment, so it is not evidence of a blind,
  preregistered evaluation; future comparisons must freeze and justify it
  before inspecting target results.

### Consequences
- The registry may retain same-size files unless their content hashes match.
- Results using the existing tolerance are exploratory and must not be
  described as preregistered.

## ADR 4 — E1 class-stratified random reference split

### Context
The first E1 allocation was random by exact-duplicate group without class
stratification. On the audited local corpus this placed no normal window in
the test partition, preventing binary evaluation.

### Decision
- Allocate exact-duplicate groups randomly but stratify by binary class so all
  partitions receive both classes whenever at least three distinct groups per
  class make this possible.
- Keep E1 a favorable random reference protocol; it does not claim
  session-independent generalization. If class coverage is impossible, retain
  an explicit non-evaluable status rather than synthesizing samples.

### Consequences
- E1 partitions and downstream metrics are regenerated from the current
  `windows_all.csv` hash; earlier splits and metrics are stale.
- The stratification controls class presence only and does not tune model
  hyperparameters or thresholds against test performance.
