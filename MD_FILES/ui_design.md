# Witness UI spec

The witness view is the SOC / auditor screen. It is the only place alerts appear. It must be readable from the back of a room.

## Layout (same on every screen)

```
+--------------------------------------------+-------------+
|                                            | Layer 1     |
|               Main panel                   | Custom cmds |
|        (changes with the active layer)     +-------------+
|                                            | Layer 2     |
|                                            | Heartbeat & |
|                                            | checksum    |
+--------------------------------------------+-------------+
|           Live heartbeat monitor           | Layer 3     |
|           (about 25% of screen height)     | Quarantine  |
+--------------------------------------------+-------------+
```

- **Main panel:** shows the detail for whichever layer is active.
- **Sidebar:** three layer cards, always visible.
- **Heartbeat monitor:** runs along the bottom on every screen. Never hidden.

## Sidebar cards

Each card has a state:

| State | Colour | Meaning |
|---|---|---|
| Idle | Grey | No activity at this layer yet |
| Passed | Green | Checks running, nothing wrong |
| Caught | Red | This layer caught something |

- When a layer catches something, its card turns red and the main panel switches to it automatically.
- Cards are clickable so the presenter can go back to an earlier layer.
- Each red card shows a small count or timestamp of when it fired.

## Heartbeat monitor

A line graph that scrolls left over time.

| Spike | Meaning |
|---|---|
| Up spike | Witness asks the server for a record (random check) |
| Down spike, green, right after | Server answered and the record matches |
| Down spike, red | Server answered but the record doesn't match (tampered) |
| No down spike after an up spike | Server didn't answer |
| Flat line | No heartbeats at all (network cut) |

Label each up spike with the record number it asked for (e.g. `#42`) so the link to the layer 2 panel is obvious.

## Screen 0: Normal

Main panel shows a calm status:
- Server name, status "Connected"
- Last verified record number and time
- Records verified so far
- All three cards green

This is the "before" picture. It needs to be on screen long enough for the audience to see it.

## Screen 1: Layer 1 caught

Main panel shows a command log table:

| Time | User | Source IP | Command | Result |
|---|---|---|---|---|

- Normal rows in default colour.
- The blocked command row highlighted red.
- Under the table: one line saying which custom rule it broke, e.g. "Direct write to log file is not in the allowed command set."

## Screen 2: Layer 2 caught

Main panel shows the tampered record side by side:

```
Record #42                      Caught by random check at 19:04:12

  Expected (witness copy)        Found on server
  account:  ACC-1031             account:  ACC-1031
  amount:   5000.00              amount:   50.00        <- red
  to:       ACC-2210             to:       ACC-2210

  hash: 3fa9...e21               hash: 91cc...07b       (small text)
```

- Show the record number and the time it was caught.
- Highlight only the changed field in red. The field diff is what people read; hashes are small proof underneath.
- If more than one record was tampered (found in the sweep after the first), list them below with record numbers.

## Screen 3: Layer 3 quarantine

Main panel shows:

1. Big status line: **"Banking server has quarantined itself. All users logged out."**
   (The witness is reporting it. It did not do the lockdown, since the network is cut.)
2. Evidence status, split in two:
   - **Verified and stored on witness:** logs from `{T1}` to `{T2}` (records 1 to N)
   - **Unverified since cut:** M records written after `{T2}`, held on the server, not yet checked
3. Key holder slots:

| Key holder | Status |
|---|---|
| SOC lead | Pending / Approved |
| Auditor | Pending / Approved |
| Compliance officer | Pending / Approved |

   "2 of 3 approvals needed to unlock." When 2 are approved, the server unlocks and status goes back to Connected.

Heartbeat monitor is flat on this screen.

## Data the UI needs from the witness backend

| Field | Used on |
|---|---|
| Connection status, last heartbeat time | Screen 0, monitor |
| Last verified record number and time | Screens 0 and 3 |
| Heartbeat events (asked #N, answered ok / mismatch / no answer) | Monitor |
| Blocked command entries (time, user, IP, command, rule) | Screen 1 |
| Mismatched records (seq, witness copy, server copy, hashes, caught time) | Screen 2 |
| Quarantine state, verified range, unverified count | Screen 3 |
| Key holder approvals | Screen 3 |

Updates should be pushed live (WebSocket or polling every second is fine for the demo).

## Not in scope for the demo

- Login on the witness view.
- Real Shamir key splitting. Approvals are buttons.
- History or search across past incidents.