# Data Card — madatasets

## Scope
- Source directory: `/home/hafid/XD-IDS_Project/madatasets`
- PCAP files audited: 27
- Canonical PCAP captures retained: 27
- Working normal labels: 2
- Working attack labels: 25
- Exact duplicate files excluded from canonical registry: 0

## Provenance and validity
- Provenance is not fully documented in the repository; the dataset is treated as a local working corpus only.
- The audit script records SHA-256, file size, packet count, and time range for every PCAP, including excluded exact duplicates.
- Only byte-identical SHA-256 matches are excluded. Similar sizes or packet counts alone are not considered proof of a duplicate.

## Canonical registry
- Registry file: `configs/captures.yaml`
- Metadata file: `data/metadata/captures.csv`

## Notes
- `device_side` is set to `orig` as a provisional assumption because the capture topology is not documented; validate before scientific evaluation.
- Labels are derived from file names and therefore remain a working assumption until the capture provenance is verified.

## Canonical captures retained
- `0day` — label=1; packets=14057; t_min=1614087102.215211; t_max=1614087396.678162
- `blackEnergy` — label=1; packets=1041; t_min=1613066289.723507; t_max=1613068272.748874
- `distcc_exec_backdoor` — label=1; packets=105; t_min=1611007766.869065; t_max=1611008172.032807
- `distcc_exec_backdoor2` — label=1; packets=105; t_min=1611007766.869065; t_max=1611008172.032807
- `hydra_ftp` — label=1; packets=3904; t_min=1611010633.155136; t_max=1611010709.303691
- `hydra_ftp2` — label=1; packets=3904; t_min=1611010633.155136; t_max=1611010709.303691
- `hydra_ssh` — label=1; packets=20078; t_min=1611010865.535134; t_max=1611010894.150611
- `hydra_ssh2` — label=1; packets=20078; t_min=1611010865.535134; t_max=1611010894.150611
- `java_rmi` — label=1; packets=49877; t_min=1611056336.912608; t_max=1611056478.346448
- `java_rmi2` — label=1; packets=49877; t_min=1611056336.912608; t_max=1611056478.346448
- `mirai` — label=1; packets=1134964; t_min=1613057924.968071; t_max=1613058141.647395
- `netbios_ssn` — label=1; packets=48150; t_min=1611011856.317567; t_max=1611011934.49964
- `netbios_ssn2` — label=1; packets=48150; t_min=1611011856.317567; t_max=1611011934.49964
- `normal` — label=0; packets=11452; t_min=1751681198.806146; t_max=1751681277.793215
- `normal2` — label=0; packets=22036; t_min=1753680154.576844; t_max=1753680232.812705
- `replayAttacks` — label=1; packets=69833; t_min=1613068332.941473; t_max=1613070152.662165
- `ruby_drb` — label=1; packets=45719; t_min=1611055397.330709; t_max=1611055453.347203
- `ruby_drb2` — label=1; packets=45719; t_min=1611055397.330709; t_max=1611055453.347203
- `smtp` — label=1; packets=913; t_min=1611011538.282444; t_max=1611011734.348623
- `smtp22` — label=1; packets=913; t_min=1611011538.282444; t_max=1611011734.348623
- `tomcat` — label=1; packets=452; t_min=1611009992.990131; t_max=1611010189.794489
- `tomcat2` — label=1; packets=452; t_min=1611009992.990131; t_max=1611010189.794489
- `unreallrcd` — label=1; packets=94549; t_min=1611009124.234083; t_max=1611009835.951557
- `unreallrcd2` — label=1; packets=94549; t_min=1611009124.234083; t_max=1611009835.951557
- `vsftpd` — label=1; packets=37173; t_min=1611011301.002179; t_max=1611011418.557871
- `vsftpd2` — label=1; packets=37173; t_min=1611011301.002179; t_max=1611011418.557871
- `zeus` — label=1; packets=2005; t_min=1614091209.371815; t_max=1614091678.297974

## Fichiers exclus (doublons exacts)
- Aucun doublon exact détecté.
