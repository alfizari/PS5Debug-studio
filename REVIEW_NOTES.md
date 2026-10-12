# Review & changes (checked against ps5debug-NG 1.3.2 PROTOCOL.md and its server source)

Your previous version is saved in `backup_6/`.

## 0. Update 2 - the tool now writes the JSON for you

* **Automatic stack frame.** Any `code` step (and the Caller's Assembler window) that calls a
  function or writes `[rsp+X]` without its own `sub rsp`/`push` now gets
  `sub rsp, N` at the start and `add rsp, N` before every `ret`, added automatically. `N` covers
  the highest `[rsp+X]` used and keeps the stack 16-byte aligned. Old cheats written the "wrong"
  way now just work. Code that already manages `rsp` is left alone. You can turn it off with the
  "auto stack frame" checkbox or `"auto_frame": false`. "Add all items" batching uses it too.
* **Insert Caller call step** now adds everything the call needs to the selected cheat and saves it:
  - an `alloc` step for every `@buffer` it uses, with the buffer's current contents as `init`
  - a `code` step for quick-code buffers, including buffers that are used only *inside* the
    assembly, such as `@stats`
  - `set` steps for the Assembler's variables
  - an input (`$param`) for every register ticked "edit", with the item list if you picked an item
  Running it again updates the code instead of duplicating it.
* **Check & fix** (Cheat Editor) finds `@buffers` a cheat uses before any step creates them. If the
  buffer exists in this session, it adds the missing `alloc`/`code` step with the current contents.
  It also warns about item lists that are not loaded.
* **Record cheat from Caller** now ticks the buffers your quick code uses as well, not only the ones
  RIP and the arguments point at.
* "All stats 99" got its missing `alloc stats` step (64 bytes of 99s).
* **Export / import.** Export saves the selected game, or one cheat, as a compact `.ps5c` file,
  about 4x smaller than the JSON. It includes the item lists the inputs use. *Copy code* gives a
  `PS5C1:...` text code for chat or forums. *Import...* (on both cheat tabs) accepts `.ps5c` files,
  JSON files and pasted codes. Imported cheats merge into the matching game (by title ID):
  - identical cheats are skipped
  - a cheat with the same name but different steps is added as "(imported)"
  - item lists are created, or missing items are added to them
* **Debugger breakpoint types.** *Add breakpoint...* (and right-click → *Breakpoint (choose type)...*
  in the Debugger, Disassembler and Scanner) offers:
  - Software (int3)
  - Hardware execute
  - Hardware write only (WRONLY)
  - Hardware read/write (RDWR)
  You choose the size (1/2/4/8), and the dialog shows how many of the 4 hardware slots are used.

## 1. Why fast calls crashed the game

ps5debug-NG runs every `CMD_PROC_CALL` (and alloc / free) by ptrace-attaching the game.
It hijacks one of its threads (`proc_call_remote_kern`) and sets `RIP = function` and `RSP -= 8`.
It writes the return address on **that thread's own stack**, runs the call, then restores the
registers. It does **not** restore the stack memory.

Your item stubs (Add Rings / Goods / Weapons / Armors / Spells) did this:

```
mov qword ptr [rsp+0x0],  ...   ; overwrites the return address
mov qword ptr [rsp+0x8],  ...   ; overwrites the hijacked thread's own stack data
mov qword ptr [rsp+0x10], ...   ; same
```

They never ran `sub rsp, ...` first, so the last two writes corrupted whatever the game thread
was holding there. The server put the registers back, but the thread then resumed with a
damaged stack. Direct calls (like Add Souls) also started with whatever stack alignment the
thread happened to have, and SSE code crashes on a misaligned stack. Each call was a gamble.
Calling every 50 ms made it many gambles a second, plus the whole game was stopped and resumed
20 times a second.

**Fixes**
* **Stack-safe calls** (`ps5debug_client.build_trampoline`, on by default; checkbox in the top bar
  and under Settings → Remote call safety). Every call goes through a 52-byte stub. The stub moves
  the stack 2 KB below the hijacked frame (well past the 128-byte red zone) and aligns it to 16.
  It leaves 256 bytes of scratch and then `call`s your function. Even old-style code that writes
  `[rsp+8]` can no longer reach the game thread. The stubs are cached per target, so this costs
  one 16 KB allocation per game run.
* **Minimum gap between hijacks** (default 150 ms, configurable). This applies to call, alloc,
  hinted alloc and free across the whole app, so scripts and "Add all items" can't fire them back
  to back.
* **No blind retries.** The client never repeats a call. "Add all items" now really uses the dialog's
  retry settings, and retry is **off by default**: a call that reported an error may still have run,
  so a retry could add the item twice. (The dialog used to ignore your checkbox and always retried 3×.)
* **Batching for "Add all items".** When a cheat is the simple `code` + `call @code` shape, several
  items are chained into one code buffer (`sub rsp,8 / call item0 / call item1 / … / ret`). That means
  **one hijack per 8 items** instead of one per item. You can change the count in the dialog;
  1 = the old behaviour.
* **`cheats/PPSA01341.json` fixed.** The item stubs now `sub rsp, 0x28` before writing the 3 stack
  arguments, `add rsp, 0x28` after the call, and end with `ret`.
* A call step can opt out of the trampoline with `"raw": true`.

Still worth knowing: the call runs on *whichever* game thread the kernel picks, while the game's
own threads are frozen. A game function that expects to run on the main/game thread can still
misbehave occasionally. The fully safe pattern is a hook on a per-frame function that drains a
queue you write to memory. The code-cave tools already have the parts for it, if you want to go
that way later.

## 2. Scanner tab (Turbo Scan)

* Uses `CC10` CAPS, `CC11` START, `CC12` COUNT, `CC13` GET, `CC14` END, `CC16` region classify,
  `CC17` cancel, plus `CC03` bulk read and `CC04` bulk write.
* The **scan runs on its own connection**, and survivors stay on the console (server-resident
  list or snapshot). A first scan over gigabytes only sends back a count, and Next Scan narrows on
  the console. The rest of the tool stays usable while a scan runs.
* Known value → `START(RESIDENT|SEGMENTS)`. If the console declines because there are too many hits,
  it falls back automatically to a snapshot plus an exact narrow, still on the console.
  Unknown initial value → `START(SNAPSHOT|SEGMENTS|KEEP_FIRST)`. Increased / decreased / changed /
  unchanged / "by" / between / bigger / smaller all work on next scans.
* Value types: Byte, 2/4/8 Bytes (signed or unsigned, hex input), Float, Double (rounded,
  exact-float and simple-values policies when the payload advertises them), String (UTF-8/16), and
  Array of bytes with `??` wildcards.
* Memory options: start/stop range, writable only, include code, skip slow or uncached GPU
  regions, fast-scan alignment, include zeros for unknown scans, and the aliasing read engine.
* Results are paged 1,000 at a time and show live values, refreshed with one bulk read every 0.6 s.
  Values that changed since the last scan turn red. The Previous and First columns are shown too.
* The **address list** works like Cheat Engine's. You can freeze entries (all frozen values go out
  in one bulk write every 100 ms), edit values, change the type, and save or load tables (`tables/*.json`).
  You can also *copy as cheat JSON*, paste-ready for the Cheat Editor.
* The right-click menu has **Find out what writes to / accesses this address**. It adds a hardware
  watchpoint in the Debugger tab.
* Cancel goes over a second connection, as the protocol requires.
* Undo scan is not possible: a server-side narrow replaces the survivor set.

## 3. Protocol review of the rest

Correct already: framing, bit-swapped status words, every struct size, the two-status write and
setregs replies, the maps/proc/info layouts, the 1184-byte debug event packet and DR6 parsing, and
the watchpoint DR7 encodings. Breakpoint disarm-while-stopped is handled the way debug.c behaves.

Fixed:
* **Stream desync.** Before, a timeout or socket error in the middle of a command left the socket
  open. The late reply was then read as the answer to the *next* command, which caused random
  wrong values and errors after any hiccup. Now every command runs inside a transaction: a
  mid-command failure closes the connection, the status turns red ("Connection lost"), and you
  press Connect.
* Long operations get their own timeouts (attach/detach 20 s, xref search 120 s, scans unlimited
  but cancellable).
* Auth (`CMD_PROC_AUTH` challenge/response) is implemented. It's needed for the turbo scan and
  bulk read.

Your data:
* The "All stats 99" cheat uses `@stats`, but no step allocates `stats`. The `code` step fails
  before the `patch` runs. Either delete the code+call steps (the patch already writes the 99s)
  or add an `alloc` step named `stats`.

## 4. GUI

* New look: clean light theme, plus a dark theme (View → Dark theme, applies on restart).
  Accent buttons, connection status dot, menu bar, Ctrl+1…7 to switch tabs.
* Settings are remembered in `settings.json`: IP, port, theme, window size, call safety.
* Clicking while something is running now **queues** the request instead of refusing it
  ("3 queued" in the status bar).
* Errors no longer pop up a modal box. They go to the status line, in red, and to the log.
* The log is batched: one UI update per 100 ms instead of one per line. "Add all items" over
  hundreds of items no longer freezes the window.
* The Cheats tab search waits until you stop typing (it used to rebuild every row on every key).
* The mouse wheel now scrolls scrollable panels while the pointer is over their child widgets.
  Before, it stopped working as soon as the pointer was over an entry or button.

## 5. Testing without the console

`python tests/mock_ps5debug.py 7444`, then connect to 127.0.0.1 port 7444 and use PID 77. The mock
speaks the wire protocol: calls, alloc, turbo scan, bulk read/write, and a "health" value that
counts down and a float that grows, so you can practise scans.
