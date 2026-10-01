# Cyber Shield Zimbabwe

**Detecting and responding to cyber threats — Cyber Shield Zimbabwe Hackathon 2026, NUST**
Theme: *Don't make it easy for them: building a cyber-strong Zimbabwe.*

A paste-and-read threat triage tool for ordinary Zimbabweans. Give it a suspicious
SMS, email, WhatsApp message or voice-note transcript. It tells you what the threat is,
how serious it is, exactly which words gave it away, what to do next, and produces an
incident report you can send to your bank or the police.

Everything runs in the browser. No account, no upload, no server. The rule engine, the
Shona and Ndebele guidance and the incident reporting work with the network cable pulled
out.

Open `index.html` and it works. Serve it once over HTTP and a service worker installs the
app shell, so it can be added to the home screen and launched offline like a normal app.
Verified: with the network fully disconnected the app still boots from cache, styles apply,
a live scan returns a verdict with its evidence, and the lab self-evaluates.

---

## Measured results

All figures are produced by the app itself, in the LAB tab, on this machine.

Presenting? `PITCH.md` is the two-minute script mapped line by line to the official
judging table, with a marks-per-criterion scorecard. `slides.html` is the deck.

| Test set | Rows | Result |
|---|---|---|
| NUST training dataset (`Cyber_Shield_Training_Dataset.csv`) | 100 (12 unique) | **100.0%** threat accuracy, **92.0%** risk-level accuracy, **0** benign messages flagged |
| Disguised scam set — slang, leetspeak, lookalike domains | 10 | **10 / 10** caught |
| Red team corpus — fresh scams never used for tuning | 21 | **18 / 21** caught |

The entire 8% risk-level gap is one message repeated eight times in the dataset, not eight
independent failures: *"We need your account details urgently to update your profile."* The
dataset labels it **Medium**; the engine scores it **High**, because six independent signals
fire on it. That is a labelling disagreement, not a detection failure — threat type is
correct on it. Lowering the threshold to match the label would push genuinely dangerous
messages down into Medium, so we left the honest score on screen.

The three red team misses are also deliberate, and the app names them:

- one voice note that carries nothing but a pre-agreed code word, which no text rule can
  see — this is the argument for a family code word, not a gap in the rules;
- two that sit on the phishing / malicious-link boundary, where the weight of the URL
  tips the class either way.

---

## How the detection works

`js/engine.js` is a deterministic, inspectable rule engine. There is no model to
download and no black box to trust.

1. **Normalise.** Unicode NFKC, strip zero-width characters, lowercase, expand chat
   shorthand (`ur` → your, `pls` → please), undo leetspeak (`p1n` → pin, `acc0unt` →
   account), and collapse stretched letters (`aaa` → aa). A flag is raised if the text
   was disguised, which itself becomes a signal.
2. **Match 28 weighted patterns.** Each rule is `[pattern, class weights, risk weight,
   reason]`. Weights accumulate per threat class, so the class with the most independent
   evidence wins rather than whichever pattern fired first.
3. **Inspect every URL.** Extract hosts, then check them against 11 real Zimbabwean
   domains (EcoCash, Econet, NetOne, Telecel, CBZ, FBC, ZIMRA, ZESA, Steward Bank,
   Innbucks, NUST). Flags brand impersonation, Levenshtein-distance misspellings
   (`zimraa.top`), lookalike subdomains (`cbz-secure.verify-account.top`), raw IP
   addresses, shortened links, unusual endings and hyphen-stuffed hosts.
4. **Read the channel.** Voice and video can be faked, so they add weight to the
   AI-enabled class — but only when the message already has another signal. An innocent
   voice note from family must not read as High.
5. **Score.** Signals sum to a risk score out of 10. Bands: Low < 2, Medium 2–4.5,
   High ≥ 4.5. A known sender and benign phrasing reduce the score; an unknown sender
   adds to it.
6. **Explain.** Every signal carries the sentence that triggered it and the exact text
   that matched, so the report can highlight it in the original message.

There is no second opinion and no fallback service. One deterministic engine produces the
entire verdict, which is why the demo cannot fail on venue wifi.

### Local-language detection, not just translation

Eleven rules cover Shona and Ndebele request phrasing — *ndiudze mharidzo*, *chikomo
chako*, *ngicela ikhasi*, *iphini yami* — split so that asking for money scores as a
financial scam and asking for a PIN or ID scores as identity fraud. A scam written
entirely in Shona is caught, not just a scam written in English.

---

## The parts that make it useful

- **Guidance in English, Shona and Ndebele**, bundled offline. Every threat class and
  every "Benign" verdict has all three. Toggling language re-renders instantly.
- **Automated incident reporting.** Each scan produces a reference such as
  `CS-ZW-1WMAXAO` — a content fingerprint, so the same message always yields the same
  reference — plus a plain-text report, a JSON evidence bundle and a Web Share sheet with a
  WhatsApp hand-off. No server involved; the files are generated in the browser.
- **A verification checklist**, not just "be careful". Each class carries the concrete
  next action: call the number inside your own app, ask for three letters of your
  account, lock your mobile money if an OTP leaked.
- **Inbox sweep.** Paste one message per line for a school, clinic or SME. Risk-sorted
  table, and any row can be opened in the full scanner.
- **Red team.** A cached corpus of 21 fresh Zimbabwean scams the engine was never tuned
  against. The misses are named on screen rather than hidden, because a tool that
  overstates itself is the problem it claims to solve.
- **Score any dataset, not just ours.** Bench 04 takes any CSV in the brief's column
  format, which is how you score the judges' held-out set in front of them.
- **Lab, four benches.** Disguised-scam scoring and self-evaluation run the moment you
  open the tab, so a judge sees evidence without pressing anything. Red team and your own
  CSV are one click each. Passing rows fold away; misses stay on screen.
- **Printable.** The incident card prints cleanly on its own, so a user can keep a paper
  record.
- **Installable and offline.** Served over HTTP, the app shell is precached and the tool
  adds to the home screen, so it launches with no network at all — the target device is a
  handset on patchy mobile data.

---

## Running it

Open `index.html`. That is the whole install.

To serve it instead:

```
python -m http.server 8000     # then open http://localhost:8000
```

Installable (PWA): served over `http://` or `https://`, the service worker precaches the
app shell and an **Install app** button appears in the header. After one visit it opens
with the network off. Opened straight off the disk via `file://` it is fully functional —
it simply cannot be installed, because browsers only register service workers on HTTP.

Files, no build step, no package manager, no dependencies:

```
index.html              markup
slides.html             the judging deck — arrow keys, n for speaker notes, f for fullscreen
manifest.webmanifest    PWA metadata and icons
sw.js                   offline app shell (stale-while-revalidate)
assets/icon-*.png       generated app icons, 192 and 512, plus a maskable variant
css/styles.css          all styling
js/engine.js            rule engine — pure logic, no DOM
js/dataset.js           the official NUST training CSV, inlined for offline scoring
js/app.js               interface, rendering, reporting, lab tools
```

`js/dataset.js` is a verbatim copy of the CSV released with the challenge brief, embedded
so the self-evaluation works with no network. `js/engine.js` touches no DOM, so it can be
run and tested under Node.

---

## Accessibility and reach

- Responsive from a 360px phone up; the demo target is an Android handset on mobile data.
- Respects `prefers-reduced-motion`; the gauge needle does not animate if the user has
  asked for less motion.
- Visible focus rings on every interactive element, keyboard-reachable signal list,
  ARIA labels and roles on the gauge and controls.
- No colour-only signalling: risk is always stated in words as well as colour.
- 67KB of app code, 106KB including the embedded training CSV. The only network request is
  the web font, and it degrades to a system font if that never loads.

---

## Known limitations

Stated plainly, because a tool that overstates itself is the problem it claims to solve.

- Risk banding disagrees with the dataset's labels on one message type; see the 92% figure
  above. Threat classification is unaffected.
- A scam that carries only a pre-agreed code word is invisible to text analysis.
- Phishing and malicious-link classification is a boundary, not a cliff.
- The rule set is English and Shona/Ndebele request phrases. It does not parse full
  Shona or Ndebele prose.
- No URL reputation feed and no phone-number intelligence, because both would need a
  live service and would break the offline guarantee.

## Team

**IdeaForge** — Dorothy Matembudze, Genius Chakanya, Dylan Zuze, Tatenda Murwira,
Revaldon Sithole.

Cyber Shield Zimbabwe Hackathon 2026, NUST.

---

## Acknowledgements

Challenge brief and synthetic training dataset from the NUST Cyber Shield Zimbabwe
Hackathon 2026. Typefaces: IBM Plex Sans and IBM Plex Mono, SIL Open Font License.
No other external code or models are used.
