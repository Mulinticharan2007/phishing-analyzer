# Phishing Email Analyser

An educational, **100% local** phishing triage tool. Paste the text of a suspicious
email, press **Analyse Email**, and get:

- a phishing **risk score from 0 to 100**,
- a classification of **Low Risk**, **Suspicious** or **High Risk**,
- a plain-English explanation of **every** warning sign that contributed, and
- practical **next steps**.

---

## The privacy promise (read this first)

**Everything happens inside your own web browser.** The email you paste is never
uploaded, saved, logged, emailed, sent to an AI provider, sent to an analytics
service or shared with anybody.

This is not a marketing claim — it is how the application is built:

| Design choice | Why it matters |
| --- | --- |
| No backend server, no database, no accounts | There is nowhere for your data to go |
| No third-party scripts, fonts, images or analytics | Opening the page makes **zero** requests to other companies |
| No `fetch`, no `XMLHttpRequest`, no tracking code | The analyser is pure text matching — it has nothing to phone home with |
| No `localStorage` or cookies | Nothing is remembered, not even between visits |
| It never opens, fetches or pings a link | Analysing a URL is not the same as visiting it |

You can prove all of this yourself: open the page, disconnect from the internet, and
it will still work perfectly.

---

## What this tool is — and what it is not

It is an **educational triage aid**. It surfaces *warning signs* so that you can
learn to spot them and slow down before acting.

It **cannot** prove that an email is malicious, and it **cannot** prove that one is
safe. A carefully written phishing email can contain none of the patterns listed
below, and an ordinary legitimate email can accidentally contain one or two. Always
treat the score as one input among several, never as a verdict.

**Safety rules that always apply:**

- Never click a suspicious link or open an attachment just to see what happens.
- Verify important messages through the organisation's official website, its official
  app, or a phone number you already trust — never through the contact details given
  in the email itself.
- If the message came to a work address, report it to your IT or security team.
- If you already entered a password or a code, change that password immediately and
  turn on multi-factor authentication.

---

## How to run it

You do not need to install anything. There is no build step and no dependencies.

1. Open the folder `phishing-analyser`.
2. Double-click **`index.html`**.

That's it — it opens in your normal web browser.

Tip: pressing **Ctrl + Enter** (or **Cmd + Enter** on a Mac) inside the text box also
starts the analysis, so you never have to reach for the mouse.

### Optional: a local preview server

Not required, but if you would like to preview it exactly as it will appear once
hosted, `python -m http.server` from this folder works. Ask me first and I will walk
you through it — it is not necessary for normal use.

---

## How the analysis works

Placing the pointer over any finding shows the exact piece of text that matched. All
of this runs in plain JavaScript in your browser.

### 1. The text is prepared

The pasted text is converted to lower case for matching, links are extracted
(without ever being visited), attachment file names are picked out, and any email
headers are unfolded and read.

### 2. Each indicator is checked

There are **23 checks**, grouped into seven families:

| Family | Example checks |
| --- | --- |
| Credential theft | asks for a password; asks for an MFA / verification code; credential-harvesting wording |
| Fraud & payment | gift card or cryptocurrency request; change of bank details; unexpected invoice |
| Social engineering | urgency and pressure language; threats of account suspension or closure |
| Impersonation | claims to be a brand or an IT/security team; impersonal greeting |
| Suspicious link | raw IP address; shortened link; look-alike domain; misleading link text |
| Dangerous attachment | executable file; macro-enabled document or "enable macros"; double extension; password-protected archive |
| Email authentication | SPF failure; DKIM failure; DMARC failure; Reply-To mismatch |

### 3. Points are added up

Each check has a **fixed** point value. If a check matches, it contributes exactly
that many points, once. The total is capped at 100.

| Check | Points |
| --- | --- |
| Asks for your password | +25 |
| Asks for an MFA / verification code | +25 |
| Executable attachment | +22 |
| Requests payment by gift card or cryptocurrency | +20 |
| Asks you to change bank or payment details | +20 |
| Link uses a raw IP address | +20 |
| Reply-To address differs from the sender | +18 |
| Link text does not match its destination | +18 |
| Macro-enabled document or "enable macros" request | +18 |
| Threatens account suspension or closure | +15 |
| Link domain imitates a known brand | +15 |
| Link uses a look-alike internationalised domain | +15 |
| Urgency and pressure language | +12 |
| Credential-harvesting wording | +12 |
| SPF authentication failure | +12 |
| DMARC policy failure | +12 |
| Attachment uses a double extension | +12 |
| DKIM signature verification failure | +10 |
| Shortened link hides its true destination | +10 |
| Unexpected invoice or payment demand | +10 |
| Claims to represent a brand or IT/security team | +8 |
| Password-protected or archive attachment | +8 |
| Impersonal, generic greeting | +5 |

### 4. The score becomes a classification

| Score | Classification |
| --- | --- |
| 0 – 24 | **Low Risk** |
| 25 – 59 | **Suspicious** |
| 60 – 100 | **High Risk** |

Because every point comes from a visible, named check, the number is never a
mystery — the results panel lists each matched check, its score contribution and the
evidence it found.

---

## The six practice examples

The application ships with six one-click examples so you can see how the tool behaves.

| Example | Expected result | What it teaches |
| --- | --- | --- |
| Obvious phishing | High Risk | Threats, deadlines, a password request and a raw IP link |
| Sophisticated phishing | Suspicious | No panic words at all — just a polite request to change bank details |
| Fake Microsoft 365 warning | High Risk | A spoofed sender where SPF, DKIM and DMARC all fail |
| Fake parcel delivery | High Risk | A short link, a small "handling fee" and a gift-card option |
| Fake invoice (BEC style) | High Risk | A colleague impersonation asking for a confidential, urgent payment |
| Legitimate email | Low Risk | Proof that ordinary email does not get flagged |

**These examples are completely fictional.** Every address and domain uses reserved
names (`.test`, `.example`, `203.0.113.x`) that can never be registered, and none of
the links do anything at all. The text is handled as plain text, never as HTML, so
nothing is ever clickable or loaded.

---

## Built-in self-tests

At the bottom of the page there is a button labelled **Run built-in self-tests**.
Clicking it runs the whole analyser against the examples and a set of synthetic
snippets, and prints a pass/fail list in the page. It currently covers 22 checks,
including:

- every example produces its expected classification,
- the legitimate email scores exactly zero,
- each individual warning sign is detected when it should be (raw IP, short link,
  look-alike domain, punycode domain, misleading link text, gift card, bank-detail
  change, Reply-To mismatch, SPF/DKIM/DMARC failures, executable, double extension,
  macros),
- ordinary legitimate emails are **not** over-flagged,
- analysing an email makes **no network requests**,
- the page references **no external resources**.

That last pair is the machine-checked version of the privacy promise.

---

## How to change how it works

You do not need to understand JavaScript to tune this. Open
`assets/js/rules.js` in Notepad or any text editor.

**To change how much a warning sign is worth:** find the check and change its
`weight` number. For example, to make password requests worth 30 instead of 25,
change `weight: 25,` to `weight: 30,`.

**To add a phrase the tool looks for:** each check has one or more patterns — strings
of text between the `PA.scan(...)` brackets. Add your phrase to the list, separated by
a `|` character.

**To add a whole new example email:** open `assets/js/demos.js` and copy one of the
`PA.DEMOS.push({ ... })` blocks, changing the `id`, `name`, `blurb`, `expected` and
`body`. It will appear as a new button automatically.

**To change which scores switch the classification:** edit the `PA.BANDS` list at the
top of `assets/js/rules.js` (the `max` value of each band).

If you would rather I made a change, just ask — that is what I am here for.


---

## Publishing it for free

Because this is a completely static website (no server, no database, no keys, no
build step), free hosting is genuinely free and needs no maintenance. Two easy
options:

**Option A — drag and drop (simplest)**

1. Create a free account at `app.netlify.com/drop`.
2. Drag the whole `phishing-analyser` folder onto the page.
3. You instantly get a public web address.

**Option B — GitHub Pages (better for learning and sharing)**

1. Create a free GitHub account and a new repository.
2. Upload these files to it.
3. In the repository settings, enable **Pages** and point it at the main branch.
4. Your site appears at `https://<your-name>.github.io/<repo-name>/`.

Cloudflare Pages works in almost the same way if you prefer it.

The order of the `<script>` tags at the bottom of `index.html` matters
(`rules.js` → `demos.js` → `analyser.js` → `ui.js` → `selftest.js`), so keep them in
that order if you edit the page.

---

## The files

```
phishing-analyser/
├─ index.html                 the page itself
├─ README.md                  this guide
└─ assets/
   ├─ css/styles.css          all the styling and the responsive layout
   └─ js/
      ├─ rules.js              the checks, their point values and the explanations
      ├─ demos.js              the six fictional example emails
      ├─ analyser.js           the analysis engine (pure logic, no screen code)
      ├─ ui.js                 screen wiring: buttons, gauge, results panel
      └─ selftest.js           the built-in self-tests
```

The engine (`analyser.js`) is deliberately kept separate from the screen (`ui.js`)
so the logic can be read and tested on its own. `rules.js` is data rather than code —
it is the list of things the tool knows how to look for.

---

## What was deliberately left out

To keep the project simple, private and free to run, this application has **no**:

- backend server, database or user accounts,
- external or paid AI services, and no API keys anywhere,
- React or any other framework, and no build step,
- analytics, telemetry, cookies or tracking of any kind,
- package dependencies to install or keep updated.

---

## Honest limitations

- Text matching is easy to fool. Attackers deliberately paraphrase and use images
  instead of words, so a clever email can score low.
- It looks at text only. It cannot verify who really sent a message, check a domain's
  true age or reputation, or scan an attachment — all of those would require going
  online, which would break the privacy promise.
- A `.com` file is a legacy program type, but `something.com` in an email body is
  almost always a web address, so the tool ignores it as an attachment. A genuinely
  attached `.com` executable would therefore be missed.
- Header checks only work if you paste the original headers. Many email apps hide
  them behind a "Show original" or "View source" option.
- When several signs match, the score stops at 100. The results panel tells you when
  that has happened.

Treat this as a teaching tool and a speed bump — a prompt to stop and check, not an
oracle.

