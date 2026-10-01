# PITCH — IdeaForge · Cyber Shield Zimbabwe

Two-minute script, mapped to the judging table in the official brief. Marks are from the
brief. Scores are our estimates. Deck: `slides.html`.

## Scorecard


| Criterion               | Marks   | Projected   | What earns it                                                           |
| ----------------------- | ------- | ----------- | ----------------------------------------------------------------------- |
| Threat detection        | 20      | 18–20      | 100.0% on all 100 official rows; 10/10 disguised; 18/21 red team        |
| Classification and risk | 15      | 14–15      | 5 classes at 100%, risk bands at 92%                                    |
| Usefulness in Zimbabwe  | 15      | 14–15      | Shona + Ndebele**detection**; 11 real ZW domains; offline; phone-first  |
| Functionality           | 15      | 15          | Everything works with the network off                                   |
| Innovation demo         | 20      | 18–20      | Fingerprinted incident report; 11 local-language rules; installable PWA |
| Ease of use             | 5       | 5           | 360px+, keyboard-reachable, no colour-only signalling                   |
| Presentation            | 10      | 9–10       | Rehearsed, one story, own limits named aloud                            |
| **Total**               | **100** | **93–100** | Biggest risk: the hidden judge dataset is unseen                        |

## The 115 seconds

**0:00 Problem** — "The scam is not English. It arrives in Shona on WhatsApp, or as a voice
note from the boss. The tools that exist need a subscription and the cloud, which is the one
thing our parents won't have when they need it. Paste the message — it tells you what it is,
how serious, which words gave it away, and what to do."

**0:12 Scanner (live)** — click *Fake ZIMRA website*, type nothing. Needle goes High,
offending words highlighted in the original.

> "It doesn't just say scam. Threat class, risk score out of ten, and the exact words that
> triggered it — plus the real domain to compare against, zimra.co.zw."

Then press **RUN SCAN** once, so they see the signals being counted. That one screen covers
four of the five required features in twenty seconds.

**0:42 Innovation 1 — reporting** — click, don't describe. Show `CS-ZW-184ZRBD`, read one
checklist line, then click **Evidence .json** so they watch the file land.

> "Same message, same reference, every time — so the citizen can show you the same case
> twice without it changing. Not 'be careful', the concrete next action. Text for the bank,
> JSON as evidence, WhatsApp hand-off. Generated in the browser, so the message never leaves
> the phone."

**1:05 Innovation 2 — localisation** — toggle the language to Shona, then Ndebele.

> "Guidance in three languages is translation. Eleven detection rules in two languages is
> localisation — the engine catches the money request and the PIN request written in Shona."

Mention offline in one sentence. **Do not demo the install live** — a failure on venue wifi
costs more than the marks win. Prove it offline if there is a Q&A slot.

**1:25 Evidence** — switch to the Lab tab; self-eval has already run.

> "We scored ourselves first. All 100 rows, same code path as a live scan: 100% threat
> accuracy, 92% risk banding, zero benign messages flagged. Then we attacked ourselves —
> 21 fresh Zimbabwean scams we never tuned against. It catches 18."

If they offer held-out data, take it: drop it into **Bench 04** and the accuracy figures
appear on screen. *"The Lab scores any CSV in the brief's format. Give me a set and I'll
score it in front of you."* This is the single strongest thing you can offer, because it
proves you were not overfitted to the 100 rows.

**1:45 The limits** — name all three misses. Do not rush this.

> "It catches 18 of 21. One is a voice note carrying nothing but a pre-agreed code word — no
> text rule can see that, which is why we tell people to agree a family code word. Two sit
> on the phishing versus malicious-link boundary, where the URL weight tips the class either
> way."

> "The 92% is one row. `TRN006` is labelled Medium in your dataset but stacks six signals,
> so it reads High. Lowering the threshold would push dangerous messages into Medium. We'd
> rather show you the disagreement than hide it."
Close: *"Four files. No build step. Open `index.html` and that is the install."* Then **stop
talking.

---

## Likely questions

**

**Rules not a model?** Deterministic,

inspectable, no network, no GPU. Every verdict traces
to a named rule. We won't hand a parent a bank decision we can't explain.

**Overfitted to 100 rows?** It's a training set — a sanity check, not a claim. The honest
number is 18 of 21 on data we never tuned against, plus 10 of 10 on disguised slang.

**Does anything leave the device?** Nothing at all. There is no second opinion to fall back
to, no upload, no server — which is exactly why every demo works offline.

**Who wrote the Shona and Ndebele?** We did. A generic detector wouldn't know *chikomo chako*
is your account and *ndiudze mharidzo* is I need details.

**Why not a real mobile app?** It already installs and launches offline, no app store, no
review queue for an elderly user. An APK is a packaging step, not a rewrite.

**Rules compliance** (only if asked): we scan nothing and contact nothing. Synthetic dataset
only, no real personal data. Only external dependencies are IBM Plex Sans and Mono, SIL OFL.
