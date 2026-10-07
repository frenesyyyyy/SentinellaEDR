# Engineering review

The portfolio cleanup starts from `c75eaf5` and preserves existing runtime policy.

Changes: replace promotional claims with source-backed documentation; remove phase
labels and redundant comments; extract desktop aggregation and pure name filters;
add regression tests and Linux build CI. The repository structure and event payloads
remain compatible. Existing releases and Git history are preserved.

The review found a gap between the README and source: unconditional kernel signal
attempts, an alert limit, a separate unused desktop MITRE path, and non-cancellable
idle shutdown. These findings are recorded in the limitations instead of being
hidden by cosmetic edits. They require focused behavioral work and VM testing.

AI-assisted work is useful here when constrained to small reviewable changes:
inspect the source, state the invariants, make the edit, inspect the diff and run
the relevant checks. Generated explanations are not evidence until checked against
the implementation. No personal performance figures or historical design motives
have been invented for this portfolio.
