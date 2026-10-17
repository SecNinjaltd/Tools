# Zero Trust Academy (v2 prototype)

A guided, hands-on course that teaches zero trust and how Microsoft security delivers it. It replaces the dashboard-first approach of the classic builder (`../Zero Trust Tool/`), which stays live.

## What's built

- **Chapter 1, The castle and the moat:** the learner plays an attacker against a perimeter network, then replays the attack against zero trust. Ends with a drag-to-sort activity and a quick check.
- **Chapter 4, Signals and decisions:** a simplified Conditional Access engine. Change user, app, device, location, sign-in method and risk, and see the decision, the policies behind it and the licence each needs. Five missions to solve.

Chapters 2, 3, 5, 6 and 7 show as "coming soon".

## Structure

| Path | Purpose |
| --- | --- |
| `index.html` | App shell (header, chapter rail, stage) |
| `css/zt2.css` | Security Ninja brand tokens (light and dark) and components |
| `js/content.js` | Chapter list and glossary text |
| `js/ui.js` | Progress store, Ninja guide, glossary popovers, quiz |
| `js/chapters/*.js` | One module per chapter, plus the reusable sort activity |
| `assets/mascots/` | Ninja, Wolfie and Shadow poses from security-ninja.com |

No build step. ES modules need to be served over HTTP (GitHub Pages, or `python3 -m http.server` from the repo root), not opened as a file.

Write `[[term]]` or `[[term|shown text]]` in chapter copy to get a hover definition from the glossary. Progress is saved in the browser only.
