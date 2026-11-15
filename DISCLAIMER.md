# ⚠️ Disclaimer & Liability Limitation

**Use at your own risk.** The code, workflows, and scripts provided in this repository (`n8n-hubspot-inbound-form-bot-honeypot-shield`) are for educational and architectural demonstration purposes. I publish them as a reference implementation from dhRobin Systems, not as a managed product or service.

## No Liability

The author and dhRobin Systems assume no responsibility or liability for any direct, indirect, incidental, special, exemplary, or consequential damages (including, without limitation, lost leads, legitimate submissions wrongly quarantined or blocked, spam that gets through, CRM data pollution, consumed enrichment or marketing credits, regulatory penalties, or business interruption) resulting from the use, misuse, or deployment of these scripts, however caused and on any theory of liability, even if advised of the possibility of such damage.

## No Warranty

All software, n8n JSON blueprints, and JavaScript modules are provided "AS IS" without warranty of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, or non-infringement. I do not warrant that the code is error-free or secure, that it is compatible with any specific version of n8n, Express, Node.js, or the HubSpot Forms API, or that it will detect any particular bot, spam campaign, or abuse pattern.

## Production Testing Required

Always test thoroughly in an isolated staging environment (for example a HubSpot developer test account or sandbox portal, and a test copy of the form) with `SANDBOX_MODE=true` and `DRY_RUN=true` enabled before connecting live HubSpot credentials. Review the quarantine log against real traffic and tune the thresholds before relying on automated blocking. Treat every blocked submission as a lead you may never see again: keep the review log, and check it.

## Detection Is Probabilistic

Risk scores come from heuristics: honeypot fields, timing, velocity, disposable-domain lists, entropy and pattern checks, ASN reputation, and header and UTM analysis. All of them produce false positives and false negatives. VPN users, corporate proxies, privacy-focused browsers, assistive technology, and people whose names don't fit English-language patterns can all trigger signals. The blocklists bundled here are incomplete and will go stale. Scores are decision support, not proof of abuse.

## Third-Party APIs & Compliance

Users are solely responsible for complying with the terms of service, rate limits, data privacy regulations (GDPR, UK GDPR, CCPA/CPRA, ePrivacy, and any other applicable law), and security policies of HubSpot, IP reputation providers, Slack, and any other connected service. That includes:

- disclosing in your privacy notice that submissions are screened for spam and abuse, including IP address, browser header, and timing analysis;
- confirming a lawful basis for processing IP addresses and browser metadata, and for sending IP addresses to a third-party ASN provider when one is enabled;
- forwarding consent and subscription choices (`legalConsentOptions`) unchanged, and never forwarding a submission whose consent you cannot honour;
- setting and enforcing a retention period for the quarantine log, which contains submitted personal data;
- honouring data subject requests (access, correction, deletion) across the review log, n8n execution data, and HubSpot;
- reviewing quarantined submissions promptly rather than letting real enquiries sit unanswered.

## Security

Signed render tokens, Origin checks, velocity limits, and sandbox interlocks reduce risk but do not eliminate it. You are responsible for protecting secrets, rotating credentials, configuring reverse proxies so client IP headers cannot be spoofed, restricting access to the admin endpoints and n8n, and keeping all dependencies patched.

## Not Professional Advice

Nothing in this repository is legal, compliance, privacy, or security advice. Consult qualified professionals for your jurisdiction and use case.

---

Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
