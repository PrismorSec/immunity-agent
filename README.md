# PR assets — fix/mirror-not-a-gateway-fanout

Reproduction artifacts for the scope/mirror fan-out fix. Not part of the
shipped package; this branch exists only so the PR can link images.

- `repro_demo.py` — self-contained reproduction. Builds a throwaway HOME and
  workspace, so it does not touch your real config:
  `python3 repro_demo.py /path/to/prismor-checkout`
- `mirror-before.png` / `mirror-after.png` — the same script on `main` and on
  the fix branch.
