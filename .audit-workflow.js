export const meta = {
  name: 'ethertunnel-security-audit',
  description: 'Multi-agent security audit of the EtherTunnel relay/client/proto with adversarial verification',
  phases: [
    { title: 'Recon', detail: 'map crates, entry points, trust boundaries' },
    { title: 'Find', detail: 'one finder per security dimension' },
    { title: 'Verify', detail: 'adversarial refutation panel per finding' },
    { title: 'Synthesize', detail: 'severity-ranked report' },
  ],
}

const REPO = '/home/mat/Documents/ethertunnel'

// ---- schemas ----
const FINDINGS_SCHEMA = {
  type: 'object',
  required: ['findings'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        required: ['title', 'severity', 'file', 'description', 'attack_scenario', 'evidence', 'recommendation', 'confidence'],
        properties: {
          title: { type: 'string', description: 'short, specific finding title' },
          severity: { type: 'string', enum: ['P0', 'P1', 'P2', 'P3'], description: 'P0=critical/exploitable-now, P1=serious, P2=moderate, P3=low/hardening' },
          file: { type: 'string', description: 'path:line, relative to repo root' },
          description: { type: 'string', description: 'what the defect is and why it is wrong' },
          attack_scenario: { type: 'string', description: 'concrete step-by-step attacker path that exploits it; "N/A - hardening" if not directly exploitable' },
          evidence: { type: 'string', description: 'verbatim code snippet (a few lines) proving the defect exists' },
          recommendation: { type: 'string', description: 'the specific fix; note if it touches the wire protocol or is behavior-changing' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
      },
    },
  },
}

const VERDICT_SCHEMA = {
  type: 'object',
  required: ['verdict', 'reasoning'],
  properties: {
    verdict: { type: 'string', enum: ['confirmed', 'refuted', 'uncertain'], description: 'confirmed=real & exploitable as described; refuted=not a real defect or mitigated elsewhere; uncertain=cannot tell' },
    corrected_severity: { type: 'string', enum: ['P0', 'P1', 'P2', 'P3', 'none'], description: 'your independent severity after re-deriving; "none" if refuted' },
    reasoning: { type: 'string', description: 'why; cite the exact code you read this turn' },
    wire_protocol_impact: { type: 'boolean', description: 'true if the recommended fix would change the wire protocol or be behavior-changing for deployed clients' },
  },
}

// ---- recon ----
phase('Recon')
const recon = await agent(
  `You are mapping the EtherTunnel codebase at ${REPO} for a security audit. EtherTunnel is an internet-facing reverse-tunnel relay: it terminates TLS for *.ethertunnel.com, accepts daemon (client) connections from anywhere, and proxies arbitrary visitor HTTP/WebSocket/raw-TCP traffic to those daemons.

Read the workspace structure: crates/{proto,relay,client,cli}. Read Cargo.toml files, crates/relay/src/lib.rs, and skim each relay source file. Produce a concise architectural map: the data/control flow, every externally-reachable entry point (who can reach it: anonymous internet visitor, any daemon, authenticated owner-daemon, operator), and the trust boundaries between them. Note where untrusted input first enters the system. This map orients the finders; be accurate and specific with file:line anchors. Output as prose, max ~600 words.`,
  { phase: 'Recon' }
)

// ---- finders ----
const DIMENSIONS = [
  {
    key: 'authn-authz',
    prompt: `Audit AUTHENTICATION, AUTHORIZATION & TOKEN HANDLING in the EtherTunnel relay. Focus: crates/relay/src/registry.rs (SQLite token registry: SHA-256 token hashing, the \`subtle\` constant-time compare, parameterized queries, label validation / reserved labels, ownership checks), crates/relay/src/session.rs (handle_claim: claim authorization, all-or-nothing ownership, supersede logic, heartbeat dead-man), crates/relay/src/auth.rs. Hunt: timing oracles in token compare/lookup, missing ownership checks, label/subdomain hijack, token generation entropy, token-in-error-message leaks, auth bypass via supersede/reclaim, race conditions in claim.`,
  },
  {
    key: 'tls-acme',
    prompt: `Audit TLS TERMINATION & ACME in the EtherTunnel relay. Focus: crates/relay/src/tls.rs (rustls config pinned to ring, SNI resolver, cert hot-swap), crates/relay/src/acme.rs (ACME DNS-01 order flow, cert/key persistence + file perms, renewal), crates/relay/src/dns_cloudflare.rs (Cloudflare API token handling, DNS-01 TXT record create/cleanup). Hunt: weak TLS config (protocol/cipher downgrade, missing ALPN), cert/key written world-readable, Cloudflare token logged/leaked, DNS-01 record left dangling, cert hot-swap race, SNI resolver returning wrong cert / default-cert info leak, missing cert validation.`,
  },
  {
    key: 'proxy-http',
    prompt: `Audit the VISITOR HTTP/WEBSOCKET PROXY in the EtherTunnel relay. Focus: crates/relay/src/proxy.rs (hop-by-hop header stripping, X-Forwarded-For rewrite, Host preservation, WebSocket upgrade byte-splice, request/response scrubbing, timeouts). Hunt the classic proxy attack surface: HTTP request smuggling (CL.TE / TE.CL, duplicate headers, chunked parsing), header injection/spoofing (can a visitor forge X-Forwarded-For / X-Real-IP?), SSRF (can a visitor reach relay-internal or metadata endpoints through the proxy?), Host header confusion / cache poisoning, WebSocket smuggling, missing timeouts enabling slowloris, response splitting, hop-by-hop header bypass.`,
  },
  {
    key: 'wire-dos',
    prompt: `Audit the WIRE PROTOCOL & DoS / RESOURCE EXHAUSTION surface of EtherTunnel. Focus: crates/proto/src/* (codec.rs, frames.rs, limits.rs: frame parsing, size caps MAX_CONTROL_FRAME / MAX_STREAM_HEADER, HELLO_TIMEOUT / SESSION_DEAD_AFTER, preamble/magic validation, integer/length handling), crates/relay/src/listener.rs (the :443 accept loop), crates/relay/src/tcp.rs (raw-TCP tunnels, port range binding), crates/relay/src/ratelimit.rs (pre-TLS per-IP rate limiting, handshake timeouts), and yamux stream-limit / second-stream handling in session.rs. Hunt: integer overflow/underflow in length parsing, unbounded allocation from attacker-controlled lengths, missing/oversized frame caps, panic-on-malformed-input (DoS via crash), missing handshake timeout (connection exhaustion), rate-limit bypass, yamux stream flooding, port exhaustion, slowloris pre-TLS.`,
  },
  {
    key: 'entitlement-ed25519',
    prompt: `Audit the NEW ENTITLEMENT / Ed25519 verification path (commit 27d4132, the least battle-tested code). Focus: crates/relay/src/entitlement.rs (Ed25519 signed-envelope verification, the canonical-bytes construction which must match keygate's signing::canonical_bytes byte-for-byte, fail-open staleness bounds, cache poisoning, the hyper-rustls poller, key_id / product / signature / expiry checks) and its enforcement in session.rs handle_claim (max_tunnels). Hunt: signature verification bypass (wrong message bytes signed/verified, missing field in canonical form, algorithm confusion, accepting unsigned), fail-open abused to grant unlimited tunnels (how long can stale/absent entitlement be exploited?), cache poisoning, key_id substitution, expiry not enforced, product mismatch accepted, replay of an old higher-tier envelope, integer issues in max_tunnels comparison, TOCTOU between entitlement check and claim.`,
  },
  {
    key: 'injection-secrets',
    prompt: `Audit INJECTION & SECRETS HANDLING across the EtherTunnel relay and client. Focus: SQL in crates/relay/src/registry.rs (any string-built/dynamic SQL, LIKE patterns, label injection), secrets at rest and in logs across crates/relay/src/config.rs, crates/relay/src/dns_cloudflare.rs, crates/client/src/config.rs, crates/client/src/credentials.rs (file permissions on token/credential/cert files, secrets in Debug/Display impls, secrets in log lines / error messages / panic messages), and any command/path/log injection. Hunt: SQL injection, secrets written world-readable, tokens/Cloudflare-API-key/private-keys appearing in logs or errors, Debug derive leaking a secret, path traversal in any file path derived from untrusted input, log injection (CRLF) from visitor-controlled values.`,
  },
  {
    key: 'client-deploy',
    prompt: `Audit the CLIENT and DEPLOYMENT hardening of EtherTunnel. Focus: crates/client/src/* (config.rs, credentials.rs, service.rs, paths.rs: credential storage permissions, relay_ca TLS trust pinning, service-install for systemd/launchd/Windows — privilege level and installed-file perms, token-in-config exposure) and deploy/* (Dockerfile static-musl/scratch build, systemd unit hardening, secret file perms e.g. /etc/ethertunnel/cloudflare.token 0600). Hunt: client trusting system roots instead of pinned relay_ca (MITM), credentials world-readable, service installed with excessive privilege or writable-by-non-root binary/unit (privilege escalation), token leaked via process args/env, Docker image running as root / shipping a shell or secrets, systemd unit missing hardening (NoNewPrivileges, ProtectSystem, etc.), world-readable secret files.`,
  },
  {
    key: 'deps-supply-chain',
    prompt: `Audit DEPENDENCIES & SUPPLY CHAIN for EtherTunnel. Read all Cargo.toml + Cargo.lock at ${REPO}. The relay pins rustls→ring and builds fully static musl (NO openssl, NO aws-lc) — verify nothing pulls those in transitively. Hunt: known-vulnerable / unmaintained crate versions (call out specific crates + versions you believe are risky and why — be precise, do not invent CVEs you cannot anchor), accidental openssl/aws-lc/native-tls pull-in that breaks the pure-ring/musl constraint, dependencies with broad unsafe / network / build-script risk, version pinning gaps, duplicate/conflicting crypto stacks. If you assert a crate is vulnerable, cite the exact version in Cargo.lock as your evidence.`,
  },
]

log(`Recon complete. Fanning out ${DIMENSIONS.length} finders, each verified by a 3-vote adversarial panel.`)
phase('Find')

const verified = await pipeline(
  DIMENSIONS,
  (d) => agent(
    `${d.prompt}

REPO: ${REPO}. Read the actual source files this turn — do not rely on assumptions. Anchor every finding to a real file:line and quote the verbatim code as evidence. Only report defects you can prove from the code you read. Prefer a few high-confidence findings over many speculative ones. If you find nothing real in this dimension, return an empty findings array — do NOT pad with hypotheticals.

Recon map for context:
${recon}`,
    { label: `find:${d.key}`, phase: 'Find', schema: FINDINGS_SCHEMA }
  ),
  // adversarial verify: each finding re-derived blind by a 3-member refutation panel
  (review, d) => parallel(
    (review?.findings || []).map((f) => () =>
      parallel(
        ['correctness', 'exploitability', 'mitigation-elsewhere'].map((lens) => () =>
          agent(
            `You are an adversarial security reviewer. Your job is to REFUTE the following claimed finding in the EtherTunnel codebase at ${REPO}. Read the cited code yourself, this turn, and try hard to prove the finding is WRONG, already-mitigated, or not actually exploitable. Default to "refuted" if you cannot independently confirm it from the code.

Examine it through the "${lens}" lens specifically:
- correctness: is the code actually as described, or did the finder misread it?
- exploitability: can a real attacker actually trigger this, given the surrounding code/config/trust boundary?
- mitigation-elsewhere: is this already handled by a check, cap, type, or layer elsewhere in the codebase?

CLAIMED FINDING:
- Title: ${f.title}
- Severity: ${f.severity}
- File: ${f.file}
- Description: ${f.description}
- Attack scenario: ${f.attack_scenario}
- Evidence given: ${f.evidence}
- Proposed fix: ${f.recommendation}

Verify against the real code. Give your independent verdict.`,
            { label: `verify:${d.key}:${lens}`, phase: 'Verify', schema: VERDICT_SCHEMA }
          )
        )
      ).then((votes) => {
        const v = votes.filter(Boolean)
        const confirmedVotes = v.filter((x) => x.verdict === 'confirmed').length
        const refutedVotes = v.filter((x) => x.verdict === 'refuted').length
        // survives if a majority of the panel confirms (>= 2 of 3)
        const survives = confirmedVotes >= 2
        return { ...f, dimension: d.key, panel: v, confirmedVotes, refutedVotes, survives }
      })
    )
  )
)

const allFindings = verified.flat().filter(Boolean)
const survivors = allFindings.filter((f) => f.survives)
log(`${allFindings.length} raw findings; ${survivors.length} survived the adversarial panel.`)

// ---- synthesize ----
phase('Synthesize')
const sevRank = { P0: 0, P1: 1, P2: 2, P3: 3 }
survivors.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9))

const report = await agent(
  `Write the final EtherTunnel security audit report as Markdown. You are given the adversarially-verified findings (each survived a >=2/3 refutation panel). Group by severity (P0, P1, P2, P3). For each finding include: title, file:line, what it is, the attack scenario, the evidence snippet, the recommended fix (flag if it touches the wire protocol / is behavior-changing for deployed clients), and the panel vote tally. Open with a 1-paragraph executive summary and a counts table (how many P0/P1/P2/P3). Close with a prioritized fix plan separating "safe to apply now" from "needs Mat's sign-off (behavior/wire-protocol changing)". Be precise and honest; do not inflate severity.

VERIFIED SURVIVING FINDINGS (JSON):
${JSON.stringify(survivors.map((f) => ({ title: f.title, severity: f.severity, dimension: f.dimension, file: f.file, description: f.description, attack_scenario: f.attack_scenario, evidence: f.evidence, recommendation: f.recommendation, confidence: f.confidence, votes: `${f.confirmedVotes}/3 confirmed` })), null, 2)}

For transparency, also note how many raw findings were proposed but did NOT survive the panel: ${allFindings.length - survivors.length} refuted/uncertain.`,
  { phase: 'Synthesize' }
)

return {
  counts: {
    raw: allFindings.length,
    survived: survivors.length,
    refuted: allFindings.length - survivors.length,
    bySeverity: survivors.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc }, {}),
  },
  survivors: survivors.map((f) => ({ title: f.title, severity: f.severity, dimension: f.dimension, file: f.file, votes: `${f.confirmedVotes}/3` })),
  report,
}
