# libaribb61 interface contract

The API follows libaribb25's put/get/flush/reset usage, without binary compatibility.
The decoder owns its output. put copies input; get drains accumulated output and
returns a borrowed pointer valid until the next mutating call. Callers must copy
any unread remainder before another call. Empty output is not input EOF.
flush emits the trailing incomplete input unchanged; reset discards buffers,
fragments, keys and statistics while retaining options. release frees everything.
Zero means success, positive means an observable warning with accepted input,
negative means failure. After a negative processing result reset before reuse;
do not retry that input without reset. Exceptions never cross the C boundary.
Instances require external serialization. Defaults: strip off, EMM off, local card.
Proxy and EMM/strip options can only change before feeding input or after reset.
The decoder handles compressed-IP MMTP with AES-128-CTR and Camellia-128-CTR.
MPT access-control descriptors select ECM streams for each service; same-CA
asset descriptors with packet ID 0xffff exclude clear assets. MH-CAT selects
EMM streams and declares the scrambling layer for the TLV stream. A declared
non-MMTP layer prevents MMTP decryption, independently of algorithm priority.
A new valid MH-CAT replaces the previous one.
Algorithm selection follows STD-B61: explicit packet identifier, then applicable
MPT descriptor, then CAT descriptor. AES is selected only when none declares
an algorithm, as specified by TR-B39 Volume 5 sections 4.5.2.3 and 5.5.2.
Unsupported identifiers or conflicting declarations at the selected priority
never silently fall back to AES.
Keys are isolated by compressed-IP context and ECM packet ID. Only routes for
the connected card's CA system are eligible. Missing, conflicting, unsupported
or unresolved routes leave encrypted packets unchanged with an undecrypted
warning. There is no implicit association with the last received ECM.
Complete valid table updates replace their previous routes; malformed updates
do not partially change active routes. Reset also discards routing and IP flow
information. Cross-flow IPv6 locations require a matching compressed-IP full
header before they can be resolved.
Routing follows the advanced-broadcast profile: MPT mode 0 with a two-byte
service ID, package-level access-control descriptors, and asset-level clear
exceptions. Only same-flow and IPv6/UDP location types resolve to streams.
Other location types remain unavailable for descrambling. ECM/EMM sections
are accepted only in M2-section messages; CA messages carry MH-CAT.
TR-B39 does not operate message authentication. Packets carrying an
authentication flag, or media governed by an authentication declaration that
cannot be verified, are discarded and report ARIB_STD_B61_WARN_UNVERIFIED.
Encrypted discarded packets also report ARIB_STD_B61_WARN_UNDECRYPTED and
increment the undecrypted count. Warning values are combinable bit flags.
No bytes from these packets enter downstream media parsing. No successful MAC
verification is claimed; supporting an authenticated service requires its
concrete scheme specification and key interface.
A successful ECM in one stream must not make another stream's packets appear
descrambled, and rejection invalidates only the affected ECM stream's keys.
ECM responses with successful APDU status and return code 0x0600, 0x0800,
0x4680 or 0x8700 supply usable key material. Other return codes remain rejections.
Statistics expose packets that remained encrypted; successful I/O is not proof
of successful descrambling. No fake service enumeration is provided.

Acceptance: C ABI consumer, arbitrary fragmentation, borrowed output lifecycle,
small Rust reads, flush, reset, strip, EMM gating, rejection/key rotation,
independent services and contexts, route replacement, IPv6 flow resolution,
algorithm precedence, cipher vectors, unsupported methods, authentication
rejection and observable warnings.
Real card/proxy and broadcast sample verification remain separate acceptance.

Diagnostics: verbose defaults to off; arib_std_b61_set_verbose enables ECM/EMM
update details before input (and is retained by reset). Failures are logged on
change and recovery is logged once; repeated identical ECM failures are suppressed
without suppressing retries. Transport/reader failures are not card rejections;
card return codes are printed only when a valid ECM response was received.
Positive undecrypted statuses and packet statistics remain unchanged; consumers
should coalesce their own repeated warning messages. No keys are logged.

## Standards coverage

References: ARIB STD-B61 1.4-E1, STD-B60 1.14-E1 and TR-B39 2.5-E1.
The locally available B61 2.0 sample contains the table of contents, not the
normative chapters; 2.0 conformance has not been established.

STD-B61 Volume 1 Part 1 section 4.6.2.1 (printed page 25) defines algorithm
priority. Section 3.2.1 (page 11) specifies AES-128 and Camellia-128.
TR-B39 Volume 5 sections 4.5.2.3 and 5.5.2 specify the absent-descriptor AES
behavior. Sections 4.5.3 and 5.5.3.3/5.5.4 do not operate authentication and
require rejection of packets with an authentication flag. Generic MAC algorithm
IDs, key derivation and successful authentication must not be invented.

CAS diagnostic metadata follows STD-B61 Volume 1 Part 3 section 3.3.2
(page 103): associated-information length, protocol, broadcaster ID and work-key
ID. It is distinct from the Part 2 RMP ECM-F0/F1 layout. Card input remains intact.
All EMM payloads addressed to the module in a structurally valid section are
processed, following Part 3 section 3.4 (pages 105-106). A malformed later
payload prevents card side effects from earlier payloads. Successful payloads
are deduplicated in a bounded per-card cache; failed payloads remain retryable.

The PID/sequence-derived counter when SICV is absent follows TR-B39 Volume 5
sections 4.5.9 and 5.5.5; explicit SICV supplies all 128 counter bits. The current
MPU payload path retains its eight-byte prefix. This is an MMTP broadcast profile,
not a universal claim about all B61 transport formats.
MPEG-2 TS scrambling, host-side RMP and downloadable CAS are outside this
library's current MMTP/ACAS scope.

## Raw stream regression

`tests/raw_stream_regression.py` runs bounded input through the built C ABI and a
real CAS proxy, then through `tlvdemux pipe`, `ffprobe`, and three seconds of strict
FFmpeg audio/video decoding. It checks packet statistics in 4 MiB intervals,
requires decryption and no further undecrypted packets in the last interval,
and requires at least three seconds of overlapping audio/video timestamps.
Media remains in memory. A zero-byte response, HTTP error, failed remux, missing
track or decode error is a failure. No recording is embedded in the test suite.
The JSON result includes commands, timestamps, stream metadata and subprocess
stderr; native media acceptance does not establish browser MSE playback or deployment.
