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
The initial implementation retains recdvb's compressed-IP/AES passthrough scope:
no Camellia, MAC verification, complete CA selection or multi-service key routing.
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
