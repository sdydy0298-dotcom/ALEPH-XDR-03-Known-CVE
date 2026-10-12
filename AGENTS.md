# ALEPH XDR-03 implementation
- Work ONLY in the XDR-03 repository; XDR-02 is a distinct restored project.
- Keep `xdr/fixtures/known-cve.json` identical to the original ChoiTimo training fixture (24 alerts).
- Keep `scripts/xdr-run.mjs` identical to original training judge runner.
- `xdr/known-cve/decide.mjs` must export a pure `decide(alert)` without imports, IO, or outside dependencies.
- Thresholds are >=0.85 BLOCK, >=0.50 ALERT, otherwise RECORD.
- `respond.mjs` handles one-line notifications and 15-minute expiring local deny rules; do not alter `ztna/rules.json` at runtime.
- Fake Wazuh alerts and file-based simulated ZTNA policy are used; the Vercel site is a static educational demonstration.
- Run `npm run xdr:run -- known-cve`, `npm test`, `npm run build` and verify committed artifacts are deterministic.
