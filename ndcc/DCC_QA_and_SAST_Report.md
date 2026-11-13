# Defence Cyber Command Website: QA and SAST Report

**Date:** 13 November 2026 | **Target:** `ndcc-site.html` (single-file site plus CMS, about 40 KB)
**Method:** automated tests in headless Chromium (Playwright) against a mocked database, upload and user layer, plus a static scan and manual code review.
**Result:** 51 of 51 automated checks pass after fixes. Four security issues and two functional bugs were found and fixed. The remaining risks below need your decision.

---

## 1. Quality Assurance

### 1.1 Results (51 checks)

| Area | Checks | Result |
|---|---|---|
| All 9 public pages render (home, about, leadership, news, publications, resources, gallery, careers, contact) | 9 | Pass |
| No broken or empty image sources | 9 | Pass |
| No horizontal overflow, desktop 1280px | 9 | Pass |
| No horizontal overflow, mobile 375px (5 key pages) | 5 | Pass |
| Hero animated fallback and news ticker present | 2 | Pass |
| "Report an Incident" heading sits above the Name field | 1 | Pass |
| News search, resource search and category filter | 2 | Pass |
| Poll vote shows results | 1 | Pass |
| CMS login: gate shown first, wrong credentials rejected, lockout after 5 failures, default login works | 4 | Pass |
| CMS: create post with image upload, change credentials, old credentials rejected | 3 | Pass |
| XSS payloads rendered inert (no injected elements, no dialogs, `javascript:` URLs blocked) | 3 | Pass |
| Accessibility basics (alt attributes, page language) | 2 | Pass |
| No JavaScript console or page errors | 1 | Pass |

### 1.2 Functional bugs found and fixed

1. **Status messages vanished (medium).** The login, save and credential-change messages could be lost. A live data update re-drew the page and the message was written to an element that had just been replaced. Messages are now written to the current element.
2. **Inconsistent date fallback (low).** A bad date could be printed unescaped. It now returns an empty string.

### 1.3 Open functional gaps

- The **Report an Incident** form is a demo and does not send anything. It needs a real secure channel before go-live.
- Only Contributor-level and higher accounts can vote in the poll, because of the hosting platform.
- Video playback and real uploads could not be tested here (see 3).

---

## 2. Static Application Security Testing (SAST)

**Scope:** pattern scan plus manual review of all dynamic HTML, URL handling, authentication logic and data flows. No external SAST engine (such as Semgrep) was available offline, so this is a targeted manual-plus-scripted review, not a full commercial scan.

### 2.1 Scan summary

| Pattern | Count | Verdict |
|---|---|---|
| `eval` / `new Function` / `document.write` | 0 | Clean |
| `innerHTML` assignments | 3 | All fed by escaped templates |
| Third-party scripts / external requests | 0 | Clean |
| Cookies / `postMessage` | 0 | Clean |
| `target="_blank"` without `rel="noopener"` | 0 | Clean |
| `sessionStorage` | 3 | Stores only a sign-in flag |
| Inline `on*=` handlers | 21 | Informational: blocks a strict CSP |

### 2.2 Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| S-01 | **High** | **Stored XSS through the post type field and the cyber advisory level.** The values were written into HTML without escaping. | **Fixed:** escaped |
| S-02 | **High** | **JavaScript injection through record IDs in the CMS Edit and Delete links.** An ID containing a quote could run script. | **Fixed:** IDs are now passed via data attributes |
| S-03 | **Medium** | **`javascript:` URLs in image, video and file fields.** An attacker with write access could plant a script link. | **Fixed:** only `/_blob/`, `https://` and `data:image/` URLs are allowed |
| S-04 | **Low** | The escape function did not handle single quotes. | **Fixed** |
| S-05 | **High (design)** | **The CMS login is a client-side gate and is not real security.** The code and the default credential hash are visible in the page source, and the lockout can be bypassed. | **Open.** See 2.3 |
| S-06 | **Medium** | **Default credentials.** Anyone given the default login can enter the CMS screen. | **Open.** Change them on first use (Security tab) |
| S-07 | **Medium** | The stored credential hash was readable by any signed-in viewer. | **Mitigated:** the `settings/auth` record is now admin-only |
| S-08 | Low | The password hash uses PBKDF2 with 100,000 iterations, below current guidance of 600,000 or more. | Open |
| S-09 | Low | File uploads are filtered by the browser's `accept` attribute only. The platform checks the types it allows. | Open |
| S-10 | Info | The incident form does not submit. When wired up, it needs server-side validation, rate limiting and spam protection. | Open |

### 2.3 What actually protects the CMS

The login screen is a convenience. **The real protection is the hosting platform's permissions:** only people granted Editor access to the page can write, upload or delete, whatever they type into the login screen. For a real deployment, authentication must run on a server, with sessions, hashed passwords stored server-side, rate limiting and ideally two-factor sign-in.

---

## 3. Not tested

- Real database permissions, uploads and the poll on the live platform (a mock was used).
- Video playback with a real MP4 or WebM file and the 20 MB limit.
- Firefox, Safari and older phones. Only Chromium was tested.
- Screen readers, colour contrast audits, performance or load testing.
- Penetration testing of the hosting platform itself.

## 4. Recommended next steps

1. Change the default CMS credentials on first sign-in.
2. Treat the current setup as a prototype. For go-live, rebuild the CMS on a real backend with server-side authentication.
3. Wire the incident form to a secure channel.
4. Run a full scan (Semgrep or similar) and a penetration test on the final production build.
