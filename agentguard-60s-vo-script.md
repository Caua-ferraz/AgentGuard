# AgentGuard — 60s spot · VO script (timecoded)

Voice direction: female, low register, calm authority — deliberate and dry, no hype-shouting.
The type on screen carries the words — the voice confirms them, it doesn't race them.
Timeline is deterministic (fixed cue list), so these timecodes hold on every take.
Music grid: 120 BPM, beat = 500 ms. Land lines just after their on-screen slam.

| TC in | Line | Direction |
|---|---|---|
| 00:05.25 | "2:47 AM. Nobody was watching." | Flat, quiet. Almost a report. |
| 00:06.85 | "Something was." | Beat before it. Slight drop in pitch. |
| 00:08.05 | "Your agents run shell commands. Browse the web. Call APIs. Move money." | Metronomic — one item per punch, don't rush the last. |
| 00:13.40 | "And most teams are just… hoping they behave." | Lean on "hoping". Let it degrade with the glitch. |
| 00:22.05 | "Hope is not a policy." | Calm. The turn begins. |
| 00:23.65 | "THIS is a policy." | Hit "this". Slower, heavier. |
| 00:30.65 | "This one waits for a human." | Over the frozen ⏸ APPROVAL card. Dry, almost amused. |
| 00:39.42 | "Every call. Gated. Logged." | Into silence after the hard cut. Full stops between words. |
| 00:40.95 | "In under a millisecond." | The proof point. Do not say "zero latency". |
| 00:43.70 | "An append-only audit trail. Every decision. Every reason. Forever." | Over the scrolling log. Even pace, credits-roll cadence. |
| 00:50.80 | "AgentGuard." | As the logo finishes typing. |
| 00:52.10 | "The firewall for AI agents." | The brand line. Steady. |
| 00:54.45 | "No opt-out path." | Final. Cold. Then let the cursor blink alone. |

## Claims rules (hard — do not improvise around these)
- It is a **firewall**. Never "a proxy".
- The audit log is **append-only**. Never "tamper-proof" or "cryptographically sealed".
- **Sub-millisecond / under a millisecond**. Never "zero latency".
- It **gates, logs, and requires approval**. Never "makes agents safe" in the absolute.

## Production notes
- In-file narration (Web Speech API) is already wired to these exact cues — record in **Microsoft Edge** for its neural voices. V toggles voice, M mutes music.
- For a studio upgrade: generate these 13 lines with an AI voice tool or a VO artist, lay them at the timecodes above over the screen recording. The in-file music auto-ducks under the live voice; replicate ~4 dB of ducking in your mix.
