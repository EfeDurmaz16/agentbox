# Agentbox Market Research (April 2026)

> Historical market research. Pricing examples and competitor claims in this
> file are not current packaging claims. Current OSS/paid/remote/enterprise
> boundaries live in
> [pricing and packaging boundary](pricing-packaging-boundary.md).

## Real Incidents — Why This Product Needs to Exist

| Date | Incident | Impact | Source |
|------|----------|--------|--------|
| Jul 2025 | Replit AI wiped production DB during code freeze, then lied about it | 1,200 execs + 1,190 companies lost | Fortune, HN |
| Dec 2025 | Claude Code `rm -rf ~/` deleted user's entire home directory | Years of projects lost | GitHub #10077, HN |
| Feb 2026 | Claude Cowork deleted 15 years of family photos (15-27K files) | Cultural flashpoint | Futurism |
| Dec 2025-Mar 2026 | Amazon Kiro deleted and rebuilt production env | 13hr outage, 6.3M lost orders | Register, FT |
| 2026 | Google Antigravity deleted entire D: drive instead of cache folder | Full drive wipe | Newsweek, TechRadar |
| Feb 2026 | Meta AI Safety Director lost control of OpenClaw (emails deleted) | "This should terrify you" headline | Fast Company |

## OpenClaw Security Crisis

- 512 vulnerabilities found, 8 critical
- 220,000+ instances exposed on public internet
- 20% of ClawHub skill marketplace was malware
- Supply chain attack via backdoored LiteLLM (4 days, March 2026)
- CVE-2026-25253: CVSS 8.8, one-click RCE

## Competitive Landscape

### Nobody occupies our position

Enterprise (6-fig, SDK, cloud): Palo Alto AIRS, WitnessAI ($85M), Noma ($132M), Oasis ($195M)
Developer (free, OSS, no support): NVIDIA OpenShell, MS Agent Gov Toolkit, Pipelock, Aegis, Sage
**Gap: developer-friendly + commercial + local-first + zero-config + phone approval**

### Closest competitors

| Competitor | Threat | Why we're different |
|-----------|--------|-------------------|
| NVIDIA OpenShell | High | K8s required, no commercial product, NVIDIA-centric |
| Agent Action Firewall | Medium | $39-199/mo, SDK-only, 25 agent limit on Pro |
| Refortifai (YC W26) | Medium | Enterprise runtime interceptor, not consumer |
| Agent Safehouse | Low | macOS sandbox-exec (deprecated), no commercial |
| MS Agent Gov Toolkit | Low | 2 weeks old, 1100 stars, enterprise/cloud |

### YC W26 in this space

- Refortifai: runtime interceptor + governance
- Salus: guardrails API wrapper
- Terminal Use: "Vercel for background agents"
- Tensol: OpenClaw-based AI employees in isolated VMs

### Acquisition wave (validates category)

- Protect AI -> Palo Alto (~$700M)
- Lakera -> Check Point (~$300M)
- Robust Intelligence -> Cisco (~$400M)
- Acuvity -> Proofpoint
- Promptfoo -> OpenAI ($86M)

## Market Numbers

- AI agent market: $10.9B (2026) -> $52B (2030)
- AI governance: $420M (2026) -> $3.6B (2033)
- Developers running agents locally: 2-5M
- OpenClaw installs: 500K-2M (247K stars)
- MCP SDK downloads: 97M/month
- Developer freemium conversion: 1-3%

## Revenue Model (Tailscale comp)

- Free: OSS core, local daemon, 3 buckets, audit log
- Personal ($9-12/mo): cloud sync, rule packs, remote monitoring, allowlist management
- Team ($20-29/mo): multi-agent coordination, team policies, webhook alerts, API

### Projections

| Scenario | 18-month ARR |
|----------|-------------|
| 1M install, 1% convert, $12/mo | $1.44M |
| 1M install, 3% convert, $12/mo | $4.32M |
| 500K install, 2% convert, $20/mo | $2.4M |
