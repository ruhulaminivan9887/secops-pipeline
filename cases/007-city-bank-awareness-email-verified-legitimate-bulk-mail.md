# Case 007: Bengali-language "online gambling awareness" email from City Bank (verified legitimate bulk mail)

| Field | Detail |
|---|---|
| Date received | 15 Nov 2026, 21:30 UTC (16 Nov 8:00 AM local) |
| Mailbox | personal Gmail (lab sample) |
| Gmail verdict | Landed in **Spam** |
| Final verdict | **Benign / legitimate bulk mailing.** No action beyond marking "Not spam". |
| Confidence | High on authentication, medium-high on ownership (public sources, not the bank's own confirmation) |
| ATT&CK | None. No malicious technique observed. |

## 1. Why it was triaged
Gmail put an unexpected bank email in Spam. Banks are a favourite phishing impersonation target, and the subject is Bengali, so I checked the headers before trusting or dismissing it.

## 2. Evidence from the original headers

| Check | Finding | Reading |
|---|---|---|
| SPF | PASS, IP 54.240.11.32, `smtp.mailfrom` is an `amazonses.com` bounce address | Passes for the **sending service** (Amazon SES), not for `thecitybank.com`. SPF alone proves little here. |
| DKIM | PASS twice: `d=thecitybank.com` and `d=amazonses.com` | The first signature is the one that matters: the From domain's own key signed the message. |
| DMARC | PASS, policy `p=QUARANTINE` | Passes through **DKIM alignment** (signing domain = From domain), not SPF alignment. A spoofer without the bank's DKIM key cannot do this. |
| From | `noreply@thecitybank.com` | Matches the DKIM domain. |
| Reply-To | `no-reply@citybankplc.com` | Different domain from From. Normally a flag, but here it is the bank's other domain (see section 3) and a no-reply address. |
| Return-Path | `...@amazonses.com` | Normal for SES bulk mail. |
| Received chain | `a11-32.smtp-out.amazonses.com` to Google over TLS 1.3 | Clean, single hop, no odd relays. |
| Bulk markers | `Precedence: bulk`, `List-Unsubscribe`, `X-Acelle-*` headers | Campaign platform (Acelle Mail) sending via SES. Typical marketing mail. |
| Message-ID of campaign | ends `@citybankplc.com` | Platform is configured with the bank's other domain, consistent with Reply-To. |
| Unsubscribe link | `https://citybulkmail.thecitybank.com/...` | Subdomain of the From domain, not a lookalike. |
| Links in body | Only the unsubscribe link and a Google Fonts stylesheet | No login page, no button, no attachment, no credential request. |
| Body | One inline JPEG (`visual_02.jpg`, referenced by `cid:`), alt text empty | Image-only content. See limitation below. |
| Plain-text part | Leaked CSS and a "জুয়া থেকে বিরত থাকুন" (stay away from gambling) preheader | Sloppy template, common in marketing tools, not an attack sign. |

## 3. Domain ownership
- Wikipedia lists `citybankplc.com` as the bank's official website and records the bank's shortening from "The City Bank Limited" to "City Bank PLC".
- `thecitybank.com` hosts at least one bank-branded service subdomain in public search results (`cityislamicdps.thecitybank.com`), which fits it being the bank's older domain.
- Conclusion: two domains, one organisation. This explains the From/Reply-To mismatch.
- Not independently proven: I did not run WHOIS or ask the bank. I treat this as strong circumstantial evidence.

## 4. Why Gmail still marked it Spam
Likely contributors (inferred, Gmail does not say): image-only body with almost no text, a bulk campaign from a shared SES pool, first contact from this sender, and a Bengali subject that Gmail's filter may score less confidently. This is a **false positive**, not a missed detection.

## 5. Limitations
- The base64 of the inline image was empty in the exported headers, so I could not view or hash it. The subject and preheader say it is a gambling-awareness message; I did not verify the picture.
- I did not open the unsubscribe link (never needed, and clicking confirms a live address).
- Authentication proves the mail was authorised by whoever controls `thecitybank.com` DNS. It does not prove the content is wise to act on.

## 6. Decision and response
1. Verdict: legitimate bank awareness mailing.
2. Action: mark **Not spam** in Gmail. Do not click anything.
3. If a similar message ever asks for a PIN, OTP, card number, or login, treat it as phishing regardless of passing headers, and report it through the bank's official channel.

## 7. What this case teaches
- A passing SPF can belong to the mail service, not the brand. Always check which domain it passed for.
- DMARC pass via DKIM alignment is the strongest quick signal in a header.
- A Reply-To mismatch is a prompt to verify ownership, not an automatic verdict.
- Spam folder placement is not evidence of malice, and authentication is not evidence of safety. Content and requested action decide.
- Together with Case 006, this is a second documented false-positive triage, which shows the habit of proving a conclusion instead of assuming it.

## 8. Detection idea (not deployed)
A mail-gateway rule that raises priority when **DMARC passes but Reply-To domain differs from From domain and the body asks for credentials**. Passing headers alone should not suppress review of the content.
