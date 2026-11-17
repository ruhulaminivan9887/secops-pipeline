# Case 006: "Updates to Terms of Service" email in Spam, verified legitimate

| Field | Value |
|---|---|
| Date and time (UTC) | Sent 2026-11-15 14:09; reviewed 2026-11-17 |
| Source | Gmail Spam folder (personal mailbox) |
| Subject / claimed sender | "Updates to Link's Terms of Service and Privacy Policy" / Link (Stripe's digital wallet) |
| Technique checked | T1566 Phishing (ruled out) |
| Verdict | **Legitimate email (not phishing).** Gmail's spam filter was a false positive. |
| Severity | Informational |

## 1. Why it looked suspicious
- A vague sender name ("Link") and a "we have updated our terms" message, which is one of the most common phishing lures.
- It was already in the Spam folder.
- Images did not load in the preview.

## 2. Evidence (from the full email headers)
Personal details removed.

| Check | Result | Why it matters |
|---|---|---|
| From domain | `email.link.com` | Sub-domain of the brand's real site `link.com` |
| SPF | PASS (sending IP belongs to Amazon SES) | The sending server is allowed to send for this domain |
| DKIM | PASS for `email.link.com` and `amazonses.com` | The message is cryptographically signed by the domain and was not changed in transit |
| DMARC | PASS with policy `p=REJECT` | The domain owner told mail providers to **reject** forged mail, the strictest setting |
| Reply-To | `link.com` | Same brand domain |
| Return-Path | `bounce.email.link.com` | Aligned with the From domain |
| Extra headers | `X-Stripe-EID`, links tracked through `email.stripe.com` | Consistent with a Stripe-built product |
| Footer | A registered business address in Dublin, Ireland | Normal for a company notice |

Content checks:
- No urgency, no threat, no request for a password, card or personal details.
- No attachment.
- Every link goes to `link.com` or `support.link.com` (some through the Stripe click tracker).
- The effective date (20 November 2026) and the "annual update" explanation are normal for a terms change.
- Delivered one second after sending, from a bulk-mail platform, which is how legitimate newsletters behave.

## 3. Investigation steps
1. Read the full headers (Gmail: **Show original**), not just the display name.
2. Confirmed SPF, DKIM and DMARC all pass, and that the passing domain is the **brand's own domain**.
3. Checked that Reply-To, Return-Path and link destinations match the same brand.
4. Read the body for pressure tactics, credential requests and attachments. None found.
5. Did **not** click any link.

## 4. Verdict and reasoning
Legitimate. Authentication alone is not enough, because a criminal can register a look-alike domain (for example `l1nk.com`) and make SPF, DKIM and DMARC pass **for that fake domain**. What makes this email trustworthy is that authentication passes **and** the domain is exactly the real brand's domain, **and** the content asks for nothing. Limit: I could not independently verify domain ownership (WHOIS) from my lab network.

## 5. Action
In a real SOC:
1. Close the report as "legitimate, not phishing".
2. Reply to the user with the reason, so they learn what to check.
3. Mark the message as "Not spam" if the user has an account with the sender.
4. To be fully sure, ask the user to open the service by typing the address themselves (not through the email) and look for the same notice.

## 6. Detection improvement
- Triage checklist to reuse (becomes the template for Case 007): sender domain, SPF/DKIM/DMARC, Reply-To and Return-Path alignment, link destinations, urgency or credential request, attachments.
- Never allow-list a sender by display name. Allow-list only a **domain with DMARC pass and a strict policy**.
- Spam filters produce false positives on legitimate bulk mail. Track them, so a real notice is not missed.
