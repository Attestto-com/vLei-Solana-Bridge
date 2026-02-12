# Security Policy

## Supported Versions

| Version | Network | Supported |
|---|---|---|
| 0.1.0 | Devnet | Yes |
| — | Mainnet | Not yet deployed |

## Reporting a Vulnerability

If you discover a security vulnerability in the vLEI Solana Bridge program, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Contact

- **Email**: security@attestto.com
- **Subject line**: `[vLEI Bridge] Security Vulnerability Report`
- **PGP**: Available upon request

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response timeline

| Action | Timeline |
|---|---|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix deployed (critical) | Within 7 days |
| Fix deployed (non-critical) | Within 30 days |
| Public disclosure | After fix is deployed and verified |

### Scope

The following are in scope:

- Anchor program logic (`programs/attestto-vlei-sbt/`)
- PDA derivation and account validation
- Groth16 proof verification
- Authority and access control checks
- Account serialization/deserialization

The following are out of scope:

- Off-chain services and APIs
- Frontend applications
- Third-party dependencies (report upstream)
- Denial of service via transaction spam (Solana network-level concern)

### Safe harbor

We will not pursue legal action against researchers who:

- Act in good faith
- Avoid accessing or modifying other users' data
- Report findings promptly
- Do not publicly disclose before a fix is deployed

## On-chain metadata

Security contact information is published on-chain at PDA `2XU1p6eMBsHKzLTSqQSzokZPq5YWCEsnoKasZVmHBpV1` (seed: `security`, program: `AT2PmPv9tJkKyR9u1nQ2YvXXEeMrLCQUhtDeiKSwxgkp`).
