# Zero Trust Academy (v2 prototype)

A guided, hands-on course in seven chapters that teaches zero trust and how Microsoft security delivers it. It replaces the dashboard-first approach of the classic builder (`../Zero Trust Tool/`), which stays live.

## Chapters

1. **The castle and the moat:** play an attacker against a perimeter network, then replay the attack against zero trust. Ends with a drag-to-sort activity and a quick check.
2. **Three principles:** switch verify explicitly, least privilege and assume breach on and off and watch how far an attacker gets. Four missions, then sort Microsoft features into the principle they serve.
3. **Six pillars:** explore identity, endpoints, applications, data, infrastructure and network, then match six real-world scenarios to the right pillar.
4. **Signals and decisions:** a simplified Conditional Access engine. Change user, app, device, location, sign-in method and risk, and see the decision, the policies behind it and the licence each needs. Five missions to solve.
5. **Stop the attack:** drag Microsoft controls onto the steps of two attacks (a fake sign-in page and ransomware through an unmanaged laptop) to break each chain.
6. **What you already own:** Wolfie checks a Microsoft 365 plan (Business Basic, Standard or Premium, F3, E3, E5 or E7) plus add-ons and shows which of 28 zero trust controls are included, need an add-on, or are pay as you go, each linked to Microsoft Learn.
7. **Build your roadmap:** drag controls into Now, Next and Later, see pillar coverage and what licences you'd need to add, and print a one-page plan.

## Structure

| Path | Purpose |
| --- | --- |
| `index.html` | App shell (header, chapter rail, stage) |
| `css/zt2.css` | Security Ninja brand tokens (light and dark) and components |
| `js/content.js` | Chapter list and glossary text |
| `js/ui.js` | Progress store, Ninja guide, glossary popovers, quiz |
| `js/drag.js` | Pointer drag that works with touch, plus tap-to-place for keyboard and screen readers |
| `js/catalog.js` | The pillars and the 28 controls used in chapters 5 to 7, each with its Microsoft Learn page |
| `js/learn.js` | Microsoft Learn links for every product named in the chapters |
| `js/licences.js` | What each plan and add-on includes, with Microsoft Learn sources (checked October 2026) |
| `js/chapters/*.js` | One module per chapter, plus the reusable sort activity |
| `assets/mascots/` | Ninja, Wolfie and Shadow poses from security-ninja.com |

No build step. ES modules need to be served over HTTP (GitHub Pages, or `python3 -m http.server` from the repo root), not opened as a file.

Write `[[term]]` or `[[term|shown text]]` in chapter copy to get a hover definition from the glossary. Progress is saved in the browser only.

Licensing changes often. When Microsoft changes a plan, update `js/licences.js` and the `CHECKED` date; every chapter reads from it.
