# Paper Build and Byte Identity

`build_identity.json` binds the shipped TeX source and PDF by SHA-256. The public-export verifier checks both hashes and extracts the PDF text for release-marker scanning.

This is the frozen July policy/methods manuscript. The current released-version case study is `evaluation/README.md` at the repository root.

To compile a review copy with a current TeX Live installation:

```bash
cd paper
mkdir -p ../artifacts/paper-review
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=../artifacts/paper-review agent-tool-contract-drift.tex
pdftotext ../artifacts/paper-review/agent-tool-contract-drift.pdf - >/dev/null
```

The release PDF is the byte identified in `build_identity.json`. A local recompilation can differ byte-for-byte because TeX engine versions and PDF timestamps are build inputs; it must not silently replace the release PDF. After any intentional source edit, rebuild in the canonical private toolchain, visually inspect every page, regenerate the build identity, and rerun the exact public-export gate.

This recipe establishes source availability and a checkable source/PDF binding. It does not imply peer review, accessibility certification, external validation, or archival publication.
