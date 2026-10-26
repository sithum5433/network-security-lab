# Network Security · Learn by Doing

Offline-first IE3122 revision with practical, deterministic classroom models.

- 15 adjustable real-world labs, one per substantive lesson.
- 73 attack/defence and mechanism walkthroughs.
- 16 calculation labs, 207 recall questions and 198 tutorial/lab answer groups.
- Plain-English glossaries, lecture references, optional Romanised Sinhala hints.
- Responsive layout; browser-local notes and recall progress with export/import.

## Open and test manually

Open [dist/index.html](dist/index.html), or run `node preview.mjs` and visit http://127.0.0.1:4173.

Choose a lesson → **Real-world lab** → read **Your task** → advance through the example → **Load comparison** → advance again. Change one control yourself and use **Run this scenario**. Results are invalidated when settings change; the other learning modes are still available.

Start with these checks:

| Lesson | Change | Expected observation |
| --- | --- | --- |
| Networking | Remote MAC → gateway MAC | First-hop delivery succeeds; IP destination stays unchanged. |
| Layer 2 | Load comparison; then select a missing static binding | Rogue traffic is blocked, but the legitimate PC is also blocked until its binding is restored. |
| STP | Lost BPDUs + Loop Guard | Port becomes loop-inconsistent; Root Guard is not the substitute. |
| Firewall | Unsolicited ACK + stateful inspection | Dropped despite the ACK flag. |
| ACL | Load comparison; switch Telnet → HTTPS | Telnet denied; HTTPS permitted. Try the wrong interface direction too. |
| IPsec | AH → ESP with authenticated encryption, transport → tunnel | Payload and original private header become hidden; gateway addresses stay visible. |
| AAA deployment | Explicit reject → timeout | Reject stops; timeout can advance to local authentication. |
| PKI | Enforce checks, then test a valid certificate | Wrong-host certificate rejected; valid identity accepted. |

## Build and verify

Node.js 20+; no package installation needed.

```sh
node build.mjs
node --test math.test.cjs labs.test.cjs
node preview.mjs
```

[course.json](course.json) is the portable study-content input. When built inside the original study workspace, the builder refreshes it from the existing study data and updates the top-level offline HTML. When this folder is checked out on its own, it builds from its own content snapshot. The original Office/PDF files are not included in this project.

## GitHub Pages

This folder is the repository root. [The workflow](.github/workflows/pages.yml) tests and builds on pushes to `main`, then deploys only `dist/`. In the repository’s Pages settings, choose **GitHub Actions** as the source. No backend, database, API key or domain is required.

Workflow references: [checkout](https://github.com/actions/checkout), [setup-node](https://github.com/actions/setup-node), [deploy-pages](https://github.com/actions/deploy-pages).

## Scope

All addresses, capacities and incidents in the new labs are teaching examples. No scanning or attack traffic is generated. State tables and protocol decisions are conceptual, not a Packet Tracer or vendor CLI emulator. Each lab states its relevant assumptions.

Separate dedicated wireless-security, IDS/IPS and BCP/DR decks were not supplied. Existing related material remains included; the app does not invent missing lectures. The IPv6 walkthrough explicitly distinguishes its explanatory extensions from the supplied address-comparison slides.

Progress is local to the browser origin. Export from the offline copy and import into the hosted version to transfer recall progress and notes. Lab settings are exploratory session state, not saved progress.
