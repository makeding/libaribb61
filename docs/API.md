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
descriptors select ECM streams for each service; same-CA asset descriptors with
packet ID 0xffff exclude clear assets. MH-CAT selects EMM streams and declares
the scrambling system for the TLV stream. Service-filtered input may omit
MH-CAT; in its absence, packets without an explicit method use AES with the
MPT-selected ECM keys. A received MH-CAT must declare layer 1, system 1 (AES);
unsupported declarations leave encrypted packets unchanged. A new valid MH-CAT
replaces the previous one.
The missing-descriptor AES choice follows ARIB TR-B39 Volume 5 sections
4.5.2.3 and 5.5.2; it applies even if CAT is present without a scrambler descriptor.
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
Explicit scrambling method IDs are not supported and remain unchanged. Message authentication
is not implemented: authenticated packets, including clear packets, remain
byte-for-byte unchanged and report ARIB_STD_B61_WARN_UNVERIFIED. Warning values
are bit flags and may be combined with ARIB_STD_B61_WARN_UNDECRYPTED.
No Camellia or MAC verification is claimed. A successful ECM in one stream must
not make another stream's packets appear descrambled, and rejection invalidates
only the affected ECM stream's keys.
ECM responses with successful APDU status and return code 0x0600, 0x0800,
0x4680 or 0x8700 supply usable key material. Other return codes remain rejections.
Statistics expose packets that remained encrypted; successful I/O is not proof
of successful descrambling. No fake service enumeration is provided.

Acceptance: C ABI consumer, arbitrary fragmentation, borrowed output lifecycle,
small Rust reads, flush, reset, strip, EMM gating, rejection/key rotation,
independent services and contexts, route replacement, IPv6 flow resolution,
unsupported methods, authentication preservation and observable warnings.
Real card/proxy and broadcast sample verification remain separate acceptance.

Diagnostics: verbose defaults to off; arib_std_b61_set_verbose enables ECM/EMM
update details before input (and is retained by reset). Failures are logged on
change and recovery is logged once; repeated identical ECM failures are suppressed
without suppressing retries. Transport/reader failures are not card rejections;
card return codes are printed only when a valid ECM response was received.
Positive undecrypted statuses and packet statistics remain unchanged; consumers
should coalesce their own repeated warning messages. No keys are logged.

## Standards coverage review

Reference: ARIB STD-B61 1.4-E1 full text. The locally available 2.0 sample
contains the table of contents, not the normative chapters; 2.0 conformance
has not been established.

Known gaps in the current MMTP/ACAS implementation:

- Volume 1 Part 1 section 4.6.2.1 (printed page 25) specifies algorithm
  selection in the order packet extension, MP table, CA table. The current
  implementation rejects explicit packet algorithms and discards MP-table
  scrambler descriptors. Its CAT-only selection does not implement that order.
- Part 1 section 3.2.1 (page 11) includes AES-128 and Camellia-128. Only
  AES-128-CTR is implemented.
- Part 1 sections 3.2.7 and 4.5/4.7 (pages 14, 24 and 27) describe message
  authentication and rejection of altered packets. Authentication descriptor
  selection and MAC verification are absent; unchanged output with an
  unverified warning is not authenticated reception.
- Volume 1 Part 3 section 3.3.2 (page 103) defines the CAS ECM prefix as
  associated-information length, protocol, broadcaster ID and work-key ID.
  Current diagnostic metadata instead interprets it using the Part 2 RMP
  ECM-F0/F1 layout. Card input is passed unchanged, but format, group and
  key-pair-count log fields are not reliable for CAS ECMs.
- Part 3 section 3.4 (pages 105-106) permits multiple EMM payloads per
  section. The current selector returns only the first matching module ID;
  subsequent payloads addressed to the same module are not processed.

The PID/sequence-derived counter when SICV is absent and the eight-byte
payload prefix boundary require the broadcast operational profile in addition
to STD-B61 (Part 1 section 4.6.2.2 and appendix section 1.4); they must not be
represented as universal defaults for all B61 input.
MPEG-2 TS scrambling, host-side RMP and downloadable CAS are outside this
library's current MMTP/ACAS scope.

## Current implementation target

Algorithm selection follows STD-B61: explicit packet identifier, then applicable
MPT descriptor, then CAT descriptor, then the TR-B39 AES default only when no
algorithm is declared. AES-128 and Camellia-128 use CTR with the selected ECM key;
unsupported or conflicting declarations never silently select AES. CAT's layer
constraint remains separate from algorithm priority.

TR-B39 Volume 5 sections 4.5.3 and 5.5.3.3/5.5.4 do not operate message
authentication. Packets carrying an authentication flag, or media governed by
an authentication declaration that cannot be verified, are discarded and report
WARN_UNVERIFIED (also WARN_UNDECRYPTED for encrypted packets). No bytes from
such packets may enter downstream media parsing. No generic MAC algorithm,
key derivation or successful authentication is inferred from an unassigned
scheme identifier. Supporting an authenticated service requires its concrete
scheme specification and key interface.

CAS diagnostic metadata follows Volume 1 Part 3, not RMP Part 2. All EMM
payloads addressed to the module in a structurally valid section are processed;
a malformed later payload prevents side effects from earlier payloads. Successful
repeated payloads are deduplicated while failed payloads remain retryable.

Acceptance includes known cipher vectors, algorithm precedence and unsupported
identifiers, missing CAT/descriptor, authentication rejection, multiple addressed
EMMs, and real raw-stream input through casproxy, tlvdemux and A/V decode.
