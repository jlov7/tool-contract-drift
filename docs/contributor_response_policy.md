# Contributor Response Policy

Status: operator policy for future public feedback. Timelines begin only after a public repository exists and an issue or discussion is actually received.

## Service Targets

These are response targets, not guarantees:

| Event | Target |
|---|---:|
| Acknowledge a substantive public report | 2 business days |
| Apply privacy, study-contamination, or redistribution containment | 1 business day |
| Classify the report and name an owner | 5 business days |
| Reproduce it or publish a bounded status update | 10 business days |
| Decide fix, document, defer, pivot, demote, or reject | 20 business days |

If a report cannot be resolved on that schedule, keep it open with a concrete blocker and next checkpoint. Silence is not a disposition.

## Triage Classes

1. **Privacy or study contamination:** hide public details when possible, preserve a minimal audit record privately, and stop publication or scoring if blinded materials may have leaked.
2. **Redistribution or provenance:** remove or quarantine disputed bytes from future artifacts while the issue is assessed. A notice, repository license label, or attribution is not permission by itself.
3. **Reproduction failure:** preserve the exact version, archive hash, corpus identity, command, environment, exit status, and observed output.
4. **Semantic or label dispute:** add the smallest counterexample and control; classify the outcome as confirmed defect, unsupported/manual-review boundary, intended behavior, or unresolved.
5. **Carrier alternative:** record whether evidence is an independent implementation, a custom configuration, a shared-policy transport, or only a proposal.
6. **Security-sensitive report:** follow `SECURITY.md`; do not turn a static descriptor label into a vulnerability claim.

## Evidence Handling

- Preserve the original report and attachments before normalization or redaction.
- Never rewrite negative feedback into a favorable result.
- Record the corpus identity and artifact hash for every reproduction.
- When a submitted case is used to tune policy or implementation, move it to the development corpus. Do not score it as held out or unseen in the same release.
- Preserve failed reproductions, policy regressions, carrier absorption, and kill recommendations in the decision record.
- Separate independent comparator behavior from results produced by reusing this repository's predicates or policy.
- Do not infer demand, adoption, validity, or correctness from traffic metrics.

## Dispositions

Every closed substantive report should state one disposition and its evidence:

- fixed and regression-tested;
- documented limitation or manual-review boundary;
- duplicate with a linked canonical record;
- cannot reproduce, with environment and commands recorded;
- deferred with a named evidence dependency;
- pivot or demotion accepted;
- rejected with a technical reason;
- release blocker pending provenance, ethics, privacy, or legal determination.

Attribution and quotations require explicit permission. Reviewer identities, private responses, custody hashes, conflict checks, compensation data, and contact details remain private unless the individual separately opts into a specific public attribution.
