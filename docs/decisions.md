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

## Décision 2026-11-13 : statut de madatasets et rôle de CIC-IDS2017

Constats :
- Les deux seules captures normales de madatasets datent du 2025-07-05 (normal) et du 2025-07-28 (normal2), tandis que les 15 captures d'attaque datent de janvier-février 2021. La date sépare parfaitement les classes : tout split chronologique est confondu avec le label.
- Chaque capture X2 est une variante de X (mêmes paquets, mêmes horodatages, adresses IP source/destination inversées, constaté sur distcc_exec_backdoor). Une paire X/X2 forme une seule session et ne doit jamais être répartie entre train, validation et test.
- Les labels de madatasets sont déduits du nom du fichier ; le contenu n'est pas vérifié (distcc_exec_backdoor.pcap montre du trafic sur le port 1099).

Décision :
- madatasets sert uniquement de test technique du pipeline, sans aucune conclusion scientifique.
- CIC-IDS2017 (Monday et Tuesday, ré-extraits avec Zeek) devient le domaine pilote pour RQ1 (E1 contre E2).
- La généralisation IoT (E3, E4) repose sur MQTT-IoTIDS2020, Bot-IoT, ToN_IoT, CICIoT2023 et XD-IoT.
