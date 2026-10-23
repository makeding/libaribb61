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
The decoder handles compressed-IP MMTP with AES-128-CTR. MPT access-control
descriptors select ECM streams for each asset; MH-CAT selects EMM streams.
Keys are isolated by compressed-IP context and ECM packet ID. Only routes for
the connected card's CA system are eligible. Missing, conflicting, unsupported
or unresolved routes leave encrypted packets unchanged with an undecrypted
warning. There is no implicit association with the last received ECM.
Complete valid table updates replace their previous routes; malformed updates
do not partially change active routes. Reset also discards routing and IP flow
information. Cross-flow IPv6 locations require a matching compressed-IP full
header before they can be resolved.
Unsupported explicit scrambling methods remain unchanged. Message authentication
is not implemented: authenticated packets, including clear packets, remain
byte-for-byte unchanged and report ARIB_STD_B61_WARN_UNVERIFIED. Warning values
are bit flags and may be combined with ARIB_STD_B61_WARN_UNDECRYPTED.
No Camellia or MAC verification is claimed. A successful ECM in one stream must
not make another stream's packets appear descrambled, and rejection invalidates
only the affected ECM stream's keys.
Statistics expose packets that remained encrypted; successful I/O is not proof
of successful descrambling. No fake service enumeration is provided.

Acceptance: C ABI consumer, arbitrary fragmentation, borrowed output lifecycle,
small Rust reads, flush, reset, strip, EMM gating, rejection/key rotation tests.
Real card/proxy and broadcast sample verification remain separate acceptance.

Diagnostics: verbose defaults to off; arib_std_b61_set_verbose enables ECM/EMM
update details before input (and is retained by reset). Failures are logged on
change and recovery is logged once; repeated identical ECM failures are suppressed
without suppressing retries. Transport/reader failures are not card rejections;
card return codes are printed only when a valid ECM response was received.
Positive undecrypted statuses and packet statistics remain unchanged; consumers
should coalesce their own repeated warning messages. No keys are logged.
