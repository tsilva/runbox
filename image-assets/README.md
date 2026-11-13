# Brand assets

The Runbox identity pairs a cobalt command capsule with a mint access gate.
Use the primary logo for repository branding and the text-free mark for icons.

- `sources/originals/` preserves untouched native Codex ImageGen outputs.
- `sources/` contains transparent sources after magenta chroma-key removal.
- `logo/` and `icon/` contain 1024 px exports.
- `web-seo/` contains reusable favicons, browser icons and a social preview.
- Root `logo.png` is cropped with a 24 px transparent margin for the README.
- `manifest.json` records export paths and dimensions.
- `provenance.json` records original source and primary export fingerprints.

The exact generation model was not exposed. No model or generation timestamp is
inferred. The final generation prompts are preserved in [prompts.md](prompts.md).

These are repository assets; Runbox has no website or browser metadata to wire.
The social preview is a deterministic layout of the primary logo on white.

Sources were keyed using the imagegen `remove_chroma_key.py` helper with border
sampling, a soft matte, thresholds 12 and 220, and despill. Exports were created
with the create-image-assets skill's `derive_assets.py` using the `web-seo` target
and verified with its `verify_assets.py` checker. Preserve the originals when
regenerating exports, then refresh the manifest and provenance hashes.
