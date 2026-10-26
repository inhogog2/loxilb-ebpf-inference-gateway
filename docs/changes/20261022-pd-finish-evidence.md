# Finish evidence for P/D decode streams (Unreleased)

## Fixed

A P/D decode stream whose generation had finished but whose `[DONE]` was lost
(vLLM's P/D path omits it for a small share of streams under concurrency) was
recorded `decode/truncated` when the idle sweep wrote the terminator, as if the
engine had gone silent mid-generation. The sweep now reads the stream's finish
evidence, written by the response framer from the events the client received:
a complete SSE data event that finished every choice, followed only by events
with no choice (the usage event of `stream_options.include_usage`) or `[DONE]`.
With it the stream is recorded a completion; the terminator is still the
gateway's, so `pd_terminator_synthesized` still counts it. Without it the
record stays `decode/truncated`, as before.

A decode backend that closed after the stream finished (a close-delimited
stream, no `[DONE]`) was counted a dead decode endpoint and the request a
`decode/error`; the client saw a cut. With the same evidence that EOF now
completes the stream: a completion recorded, no death counted, the terminator
written by the connection's owner. Without it the EOF stays the engine's death.

Null, error, incomplete or oversized events, a later event with content or an
error, and a data event still partial cannot prove a finish. The tracker's two
bounded 4 KiB buffers are allocated only for a P/D decode stream, on its first
body bytes, and freed with the connection; other connections carry one byte.
