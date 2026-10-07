# Design decisions

These records explain the trade-offs visible in the code. They are a retrospective
review, not a claim that each choice had a formal design record when first written.

## 1. Tracepoints rather than periodic process scans

Capture events as syscalls enter the kernel instead of repeatedly scanning the
process table. This provides an event stream even for short-lived activity.
The cost is kernel/privilege dependence and an ABI-sensitive tracepoint layout.
An entry event cannot establish that execution or a connection succeeded.

## 2. Fixed records over a ring buffer

Bounded records keep the kernel side allocation-free and make the transport easy
to inspect. The shared crate defines both ends of the layout. The trade-off is
truncated names, no argv and a finite buffer that silently drops on reservation
failure. A future loss counter is more useful than claiming guaranteed delivery.

## 3. Batch ordinary display events, deliver alerts directly

A busy desktop can produce more rows than a person can inspect. Batch by process
name and event type and show a count with the latest event. Alerts bypass that
batch, but memfd/restricted alerts still have a rate limit. The trade-off is loss
of individual event detail, including distinct destinations with the same key.
This is a display policy, not a replacement for a durable event sink.

## 4. Keep deterministic helpers separate from application state

The cleanup extracts aggregation and name filters from the desktop entry point
without changing their conditions, keys, payloads or call order. This makes those
parts reviewable and testable without redesigning concurrent startup/shutdown.
The remaining lifecycle and network logic still need a dedicated follow-up;
moving them during a documentation pass would create unnecessary behavioral risk.

## 5. Treat heuristic labels as hypotheses

Name matching and regular network timing are understandable prototype rules.
They can also match legitimate software or miss renamed tools. MITRE labels in
the core library are classification hints, not validated attack detections.
The next useful work is measuring false positives and policy outcomes, rather
than expanding the marketing claims.
