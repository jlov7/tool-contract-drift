# Community Feedback Guide

This guide covers feedback on the experimental utility, released-version case study and synthetic regression corpus. Private staging is not a public release or external validation; repository visibility and workflow results must be checked at the exact commit.

## What Feedback Is Useful

The most useful reports change an engineering or research decision:

- a command or public package that does not reproduce;
- a minimal false positive, false negative, or uncertain-containment case;
- an official protocol default or schema rule that the policy handles incorrectly;
- a real before/after descriptor pair that may be shared lawfully;
- a simpler carrier such as an existing MCP review process, Spectral wrapper, oasdiff extension, registry check, library, paper-only artifact, or kill decision;
- a provenance, attribution, license, or redistribution objection;
- a reason the claimed reapproval vocabulary is confusing or not useful in actual approval work.

Use the matching structured issue form when you have access to the repository. A private staging repository does not provide an open public feedback channel.

## Evidence Boundaries

The public surface is `public-reproduction-53`: a separate manifest-bound corpus identity with 53 project-authored synthetic descriptor pairs and the result generated from those exact bytes. It retains 28 project-authored synthetic regression cases from `private-canonical-65` byte-for-byte and adds 25 newly authored synthetic quiet controls. It is not a subset of the private corpus and contains 0 source-derived descriptor bytes. No external reproduction has yet been recorded, and a result from one corpus must not be described as a result from the other.

Configured-policy and oasdiff-adapter parity show that the authored policy can travel through other carriers. They are not independent comparator accuracy, false-positive, or false-negative evidence because they reuse or map the same policy semantics.

Do not submit:

- active-study assignments, answer keys, gold labels, coordinator maps, custody records, or reviewer identities;
- secrets, access tokens, personal contact data, payment data, employer/client-confidential material, or confidential legal advice;
- third-party source bytes without a defensible right to redistribute them;
- a case advertised as held out after maintainers have inspected it.

For sensitive security or privacy reports, follow `SECURITY.md` and use a private reporting route only after the project owner has configured and verified one. Do not improvise a public disclosure channel.

## Discussion Questions

Future MCP community discussion should ask:

1. Are these reapproval concepts useful and named correctly?
2. Which cases are unsound, noisy, or missing?
3. Should the vocabulary live in an existing protocol, registry, diff, lint, or governance surface?
4. Which real descriptor pairs can be shared with defensible provenance for a future, separately frozen evaluation?
5. What evidence would justify promotion, pivot, demotion, or termination?

The aim is counterexamples, reproductions, and upstream-carrier judgment. Agreement, stars, downloads, impressions, and ranking are not validation evidence.

## Official Process References

- MCP community and governance: <https://modelcontextprotocol.io/community/governance>
- MCP SEP guidelines: <https://modelcontextprotocol.io/community/sep-guidelines>
- GitHub issue-form syntax: <https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/syntax-for-issue-forms>

Community discussion does not imply MCP endorsement, adoption, or a standards-track proposal. A SEP should be proposed only if maintainers judge the problem and scope appropriate.
