"""Non-UI cheat state shared by the Cheat Editor and Cheats (play) tabs.

Both tabs hold the same CheatsStore instance, so enabling a toggle cheat,
editing an input value, or reloading from disk in one tab is reflected in
the other immediately.
"""

from __future__ import annotations

import threading
import time
import tkinter as tk
from pathlib import Path
from typing import Callable, Optional

import re

import asmgen
from cheats import Cheat, CheatError, Game, Runtime, TitleMismatch, execute, load_games, parse_param

Key = tuple[str, str]  # (str(game.path), cheat.name)


class CheatsStore:
    def __init__(self, app, make_buffer: Callable, folder: Path) -> None:
        self.app = app
        self.make_buffer = make_buffer
        self.folder = folder
        self.games: list[Game] = []
        self.enabled: set[Key] = set()
        self.undo: dict[Key, list] = {}
        self.param_text: dict[tuple[Key, str], str] = {}
        self.verify = tk.BooleanVar(value=True)
        self.title_ignored: set[str] = set()      # game files whose title-id mismatch the user chose to ignore
        self.state_pid: Optional[int] = None      # process the ON cheats were turned on in
        pv = getattr(app, "pid_var", None)
        if pv is not None:                        # picking another process resets the ON states
            pv.trace_add("write", lambda *_: self._pid_typed(pv.get()))
        self._listeners: list[Callable[[], None]] = []
        self._state_listeners: list[Callable[[], None]] = []

    def on_change(self, fn: Callable[[], None]) -> None:
        self._listeners.append(fn)

    def _notify(self) -> None:
        """The cheat list itself changed (reload / edit): views rebuild."""
        for fn in self._listeners:
            fn()

    def on_state(self, fn: Callable[[], None]) -> None:
        self._state_listeners.append(fn)

    def _notify_state(self) -> None:
        """Only on/off state changed (a cheat ran): views just restyle in place."""
        for fn in self._state_listeners:
            fn()

    # ------------------------------------------------------------- loading
    def reload(self) -> None:
        self.games, errors = load_games(self.folder)
        for e in errors:
            self.app.log_line(f"cheat file error: {e}")
        total = sum(len(g.cheats) for g in self.games)
        self.app.log_line(f"loaded {len(self.games)} game file(s), {total} cheat(s)")
        self._notify()

    @staticmethod
    def key(game: Game, cheat: Cheat) -> Key:
        return (str(game.path), cheat.name)

    def is_enabled(self, game: Game, cheat: Cheat) -> bool:
        return self.key(game, cheat) in self.enabled

    # ------------------------------------------------------------- params
    def lookup_for(self, p: dict) -> Optional[Callable[[str], Optional[int]]]:
        lst = p.get("items", "")
        return (lambda t: self.app.items.lookup(lst, t)) if lst else None

    def resolved(self, p: dict, text: str) -> tuple[Optional[str], bool]:
        """Returns (display text, is_error) for the current value of one param."""
        try:
            v = parse_param(str(p.get("type", "u32")), text, self.lookup_for(p))
            return (f"0x{v:X} ({v})" if isinstance(v, int) else str(v)), False
        except CheatError as exc:
            return str(exc), True

    def param_var_text(self, key: Key, p: dict) -> str:
        return self.param_text.get((key, p["name"]), str(p.get("default", "")))

    def set_param_text(self, key: Key, name: str, text: str) -> None:
        self.param_text[(key, name)] = text

    def collect_params(self, cheat: Cheat, key: Key, skip: Optional[str] = None) -> dict:
        out = {}
        for p in cheat.params:
            if skip is not None and p["name"] == skip:
                continue
            text = self.param_var_text(key, p)
            try:
                out[p["name"]] = parse_param(str(p.get("type", "u32")), text, self.lookup_for(p))
            except CheatError as exc:
                raise ValueError(f"{p.get('label') or p['name']}: {exc}") from None
        return out

    # ------------------------------------------------------------ on/off state
    def forget(self, game: Optional[Game] = None, cheat: Optional[Cheat] = None, why: str = "") -> int:
        """Mark cheats as OFF without touching the game (it crashed / was closed / restarted).
        No game = every game.  Returns how many were ON."""
        keys = [k for k in self.enabled
                if (game is None or k[0] == str(game.path)) and (cheat is None or k[1] == cheat.name)]
        for k in keys:
            self.enabled.discard(k)
            self.undo.pop(k, None)
        if game is None:
            self.undo.clear()
        if keys:
            self.app.log_line(f"marked {len(keys)} cheat(s) as off" + (f" ({why})" if why else ""))
        self._notify_state()
        return len(keys)

    def _check_pid(self, pid: int) -> None:
        """Cheats that are ON belong to one process.  A new pid means the game was restarted (or
        crashed): those patches are gone, so the ON states and saved original bytes are reset."""
        if self.enabled and self.state_pid is not None and pid != self.state_pid:
            self.forget(why=f"process changed {self.state_pid} -> {pid}, the game was restarted")
        if self.state_pid != pid:
            self.state_pid = pid

    def _pid_typed(self, text: str) -> None:
        try:
            pid = int(str(text).strip(), 0)
        except ValueError:
            return
        if pid > 0:
            self._check_pid(pid)

    def _verify_for(self, game: Game) -> bool:
        return self.verify.get() and str(game.path) not in self.title_ignored

    def _ask_title(self, game: Game, exc, retry: Callable[[], None]) -> None:
        """Main thread: title-id mismatch -> let the user ignore it (remembered until the tool closes)."""
        from tkinter import messagebox
        if messagebox.askyesno(
                "Different game",
                f"The selected process (pid {exc.pid}) is title {exc.actual or '?'}, but these cheats are for "
                f"{game.name} [{exc.expected}].\n\n"
                "Cheats for another game or region patch the wrong code and can crash it.\n\n"
                f"Ignore the mismatch and run anyway?\n(Remembered for {game.name} until you close the tool.)",
                icon="warning"):
            self.title_ignored.add(str(game.path))
            self.app.log_line(f"title id check ignored for {game.name} ({exc.actual} != {exc.expected})")
            retry()
        else:
            self.app.log_line(f"not run: {exc}")

    def _ask_mark_off(self, game: Game, cheats: list, err: str) -> None:
        """Main thread: turning off failed - offer to just mark the cheats as off."""
        from tkinter import messagebox
        names = "\n".join("  " + c.name for c in cheats[:12]) + ("\n  ..." if len(cheats) > 12 else "")
        if messagebox.askyesno(
                "Could not turn off",
                f"Turning off failed:\n{err}\n\n{names}\n\n"
                "If the game crashed, was closed or restarted, its patches are already gone - "
                "mark these cheats as OFF?\n\n(No = keep them ON, e.g. to try again.)", icon="warning"):
            for c in cheats:
                self.forget(game, c, "turning off failed")
        else:
            self._notify_state()

    # -------------------------------------------------------------- run
    def run(self, game: Game, cheat: Cheat, force_off: bool = False, force_on: bool = False,
            on_done: Optional[Callable[[bool], None]] = None) -> None:
        """Runs (or disables) a cheat in the background. `on_done(off)` fires
        on the main thread after it finishes, before any error dialog."""
        app = self.app
        key = self.key(game, cheat)
        off = force_off or (cheat.mode == "toggle" and key in self.enabled and not force_on)
        if off and cheat.mode == "toggle" and key not in self.enabled and not cheat.off:
            app.log_line(f"'{cheat.name}' is not enabled")
            return
        try:
            pid = app._pid()
        except Exception as exc:
            if off:                                     # no process any more: nothing to restore
                self._ask_mark_off(game, [cheat], f"no process selected ({exc})")
            else:
                app._fail(exc)
            return
        self._check_pid(pid)
        if off and key not in self.enabled and not cheat.off:
            self._notify_state()                        # was reset just now (game restarted)
            return
        try:
            params = self.collect_params(cheat, key)
        except ValueError as exc:
            if off:
                params = {}
            else:
                from tkinter import messagebox
                messagebox.showerror("Cheats", str(exc))
                return
        undo = self.undo.setdefault(key, [])
        verify = self._verify_for(game)
        root = app.root

        def log(msg: str) -> None:
            root.after(0, lambda m=msg: app.log_line(m))

        def work() -> None:
            root.after(0, lambda: app.log_line(f"{'disable' if off else 'run'} cheat: {cheat.name}"))
            try:
                execute(cheat, game, app.client, app.state, pid, self.make_buffer,
                        log, undo, off=off, verify_title=verify, params=params)
            except TitleMismatch as exc:
                if off:
                    root.after(0, lambda e=str(exc): self._ask_mark_off(game, [cheat], e))
                else:
                    root.after(0, lambda e=exc: self._ask_title(
                        game, e, lambda: self.run(game, cheat, force_off, force_on, on_done)))
                return
            except Exception as exc:
                if off:
                    root.after(0, lambda e=str(exc): self._ask_mark_off(game, [cheat], e))
                    return
                if isinstance(exc, CheatError):
                    raise RuntimeError(str(exc)) from exc
                raise
            if not off:
                self.state_pid = pid
            if cheat.mode == "toggle":
                (self.enabled.discard if off else self.enabled.add)(key)
            rax = app.state.last_rax
            root.after(0, lambda: self._after_run(game, cheat, rax, off, on_done))

        app._run_bg(work, f"Cheat: {cheat.name}...")

    def turn_all_off(self, game: Game) -> None:
        """Turn off every ON toggle cheat of `game` in one go; if that fails (the game crashed /
        closed), ask once whether to mark them all as off."""
        app = self.app
        on = [c for c in game.cheats if c.mode == "toggle" and self.is_enabled(game, c)]
        if not on:
            return
        try:
            pid = app._pid()
        except Exception as exc:
            self._ask_mark_off(game, on, f"no process selected ({exc})")
            return
        self._check_pid(pid)
        on = [c for c in on if self.is_enabled(game, c)]
        if not on:
            return
        verify = self._verify_for(game)
        root = app.root

        def log(msg: str) -> None:
            root.after(0, lambda m=msg: app.log_line(m))

        def work() -> None:
            failed, err = [], ""
            for c in on:
                key = self.key(game, c)
                log(f"disable cheat: {c.name}")
                try:
                    execute(c, game, app.client, app.state, pid, self.make_buffer, log,
                            self.undo.setdefault(key, []), off=True, verify_title=verify, params={})
                    self.enabled.discard(key)
                except Exception as exc:
                    failed.append(c)
                    err = err or str(exc)
                    if not app.client.connected:
                        break
            if failed and not app.client.connected:
                failed = [c for c in on if self.is_enabled(game, c)]

            def done() -> None:
                app.log_line(f"turned off {len(on) - len(failed)} of {len(on)} cheat(s) of {game.name}")
                self._notify_state()
                if failed:
                    self._ask_mark_off(game, failed, err)
            root.after(0, done)

        app._run_bg(work, f"Turning off {len(on)} cheat(s)...")

    # ------------------------------------------------------ run for every item
    def run_items(
        self,
        game: Game,
        cheat: Cheat,
        pname: str,
        items: list,
        delay_ms: int = 250,
        stop_on_error: bool = True,
        cancel: Optional[threading.Event] = None,
        on_progress: Optional[Callable] = None,
        on_done: Optional[Callable[[int, int, bool], None]] = None,
        retry_failed: bool = False,
        max_retries: int = 1,
        batch: int = 1,
    ) -> bool:
        """Run a cheat once per item, retrying failed executions.

        max_retries is the number of additional attempts after the first.
        Callbacks are dispatched to the main thread.
        """

        app = self.app
        key = self.key(game, cheat)

        if app._busy:
            app.log_line(
                "busy: wait for the current request (or press Force reset)"
            )
            return False

        try:
            pid = app._pid()
            base = self.collect_params(cheat, key, skip=pname)
        except Exception as exc:
            from tkinter import messagebox
            messagebox.showerror("Cheats", str(exc))
            return False

        p = next(x for x in cheat.params if x["name"] == pname)
        is_float = str(p.get("type", "u32")).lower() in ("f32", "f64")
        self._check_pid(pid)
        undo = self.undo.setdefault(key, [])
        verify = self._verify_for(game)
        again = dict(game=game, cheat=cheat, pname=pname, items=items, delay_ms=delay_ms,
                     stop_on_error=stop_on_error, cancel=cancel, on_progress=on_progress, on_done=on_done,
                     retry_failed=retry_failed, max_retries=max_retries, batch=batch)
        root = app.root
        total = len(items)
        max_retries = max(0, int(max_retries))

        def log(msg: str) -> None:
            root.after(0, lambda m=msg: app.log_line(m))

        def progress(i: int, name: str, err: Optional[str]) -> None:
            if on_progress:
                root.after(
                    0,
                    lambda i=i, name=name, err=err:
                        on_progress(i, total, name, err)
                )

        batch_plan = self.batch_plan(cheat, pname) if batch > 1 else None
        if batch > 1 and batch_plan is None:
            app.log_line(f"'{cheat.name}' is not a simple code+call cheat - running items one by one")

        def work() -> None:
            ok = failed = 0
            cancelled = False
            if verify and game.title_id:                 # check once, before the first item
                info = app.client.proc_info(pid)
                if info.titleid.strip().upper() != game.title_id.upper():
                    exc = TitleMismatch(pid, info.titleid.strip(), game.title_id.upper())
                    root.after(0, lambda: self._ask_title(game, exc, lambda: self.run_items(**again)))
                    return

            log(
                f"run '{cheat.name}' for {total} item(s) "
                f"of '{p.get('items', '')}'"
                + (f" in batches of {batch} (one remote call per batch)" if batch_plan else "")
            )
            if batch_plan:
                ok, failed, cancelled = self._run_batched(
                    game, cheat, pname, items, base, is_float, batch, batch_plan, pid, verify,
                    delay_ms, stop_on_error, cancel, log, progress)
                items_iter = []
            else:
                items_iter = items

            for n, (name, value) in enumerate(items_iter, 1):
                if cancel is not None and cancel.is_set():
                    cancelled = True
                    break

                params = dict(base)
                params[pname] = float(value) if is_float else int(value)

                log(
                    f"[{n}/{total}] {name} = {value} "
                    f"(0x{int(value) & 0xFFFFFFFFFFFFFFFF:X})"
                )

                attempts = 1 + (max_retries if retry_failed else 0)
                item_succeeded = False
                last_error = None

                for attempt in range(1, attempts + 1):
                    if cancel is not None and cancel.is_set():
                        cancelled = True
                        break

                    if attempt > 1:
                        log(
                            f"  RETRY {attempt - 1}/{max_retries}: "
                            f"{name}"
                        )

                        # Wait before retrying; cancellation interrupts the wait.
                        if cancel is not None:
                            if cancel.wait(max(0, delay_ms) / 1000.0):
                                cancelled = True
                                break
                        elif delay_ms > 0:
                            time.sleep(delay_ms / 1000.0)

                    try:
                        execute(
                            cheat,
                            game,
                            app.client,
                            app.state,
                            pid,
                            self.make_buffer,
                            log,
                            undo,
                            off=False,
                            verify_title=False,          # checked once above
                            params=params,
                        )

                        item_succeeded = True
                        last_error = None
                        break

                    except Exception as exc:
                        last_error = str(exc)

                        log(
                            f"  ATTEMPT {attempt}/{attempts} FAILED: "
                            f"{name}: {exc}"
                        )

                if cancelled:
                    break

                if item_succeeded:
                    ok += 1
                    progress(n, name, None)
                else:
                    failed += 1
                    progress(n, name, last_error or "Unknown error")

                    if stop_on_error:
                        log("  Stopping because stop_on_error is enabled.")
                        break

                if delay_ms and n < total:
                    if cancel is not None:
                        if cancel.wait(delay_ms / 1000.0):
                            cancelled = True
                            break
                    else:
                        time.sleep(delay_ms / 1000.0)

            if cheat.mode == "toggle" and ok:
                self.enabled.add(key)
                self.state_pid = pid

            def finish() -> None:
                app._refresh_buf_tree()
                app.log_line(
                    f"items done: {ok} ok, {failed} failed"
                    + (", cancelled" if cancelled else "")
                )
                self._notify_state()

                if on_done:
                    on_done(ok, failed, cancelled)

            root.after(0, finish)

        app._run_bg(work, f"Cheat: {cheat.name} (all items)...")
        return True

    # ------------------------------------------------ batched 'add all items'
    _LABEL = re.compile(r"^\s*[A-Za-z_.$][\w.$]*\s*:", re.M)

    def batch_plan(self, cheat: Cheat, pname: str) -> Optional[tuple[str, str]]:
        """(code name, asm) when the cheat is exactly [code X (uses $pname), call @X] - the shape
        whose per-item work can be chained into one remote call; None otherwise."""
        st = cheat.steps
        if len(st) != 2 or not all(isinstance(x, dict) for x in st):
            return None
        code, call = st
        if str(code.get("op", "")).lower() != "code" or str(call.get("op", "")).lower() != "call":
            return None
        name, asm = str(code.get("name", "")), str(code.get("asm", ""))
        if str(call.get("rip", "")).strip() != f"@{name}" or call.get("args"):
            return None
        if not re.search(rf"\${re.escape(pname)}\b", asm) or self._LABEL.search(asm):
            return None
        return name, asm

    def _run_batched(self, game, cheat, pname, items, base, is_float, batch, plan, pid, verify,
                     delay_ms, stop_on_error, cancel, log, progress):
        """Chain `batch` items into one code buffer:  sub rsp,8 / call b0 / call b1 ... / add rsp,8 / ret
        so the game thread is borrowed once per batch instead of once per item."""
        app = self.app
        name, asm = plan
        if verify and game.title_id:
            info = app.client.proc_info(pid)
            if info.titleid.strip().upper() != game.title_id.upper():
                raise RuntimeError(f"pid {pid} is title '{info.titleid}', cheat is for {game.title_id}")
        rt = Runtime(app.client, app.state, pid, self.make_buffer, log, [])
        for k, v in base.items():
            if isinstance(v, str):
                rt.strs[k] = v
            else:
                if isinstance(v, float):
                    rt.fparams[k] = v
                rt.vars[k] = int(v) & 0xFFFFFFFFFFFFFFFF
        pat = re.compile(rf"\${re.escape(pname)}\b")
        ok = failed = 0
        cancelled = False
        total = len(items)
        for start in range(0, total, batch):
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            chunk = items[start:start + batch]
            head = ["sub rsp, 8"] + [f"call __item{i}" for i in range(len(chunk))] + ["add rsp, 8", "ret"]
            body = []
            for i, (_n, value) in enumerate(chunk):
                v = int(value) & 0xFFFFFFFFFFFFFFFF if not is_float else int(float(value))
                block = asmgen.auto_frame(asmgen.substitute(pat.sub(f"0x{v:X}", asm), rt.ev))[0]
                block = asmgen.ensure_ret(block, True)
                body += [f"__item{i}:", block]
            names = ", ".join(n for n, _v in chunk)
            log(f"[{start + 1}-{start + len(chunk)}/{total}] {names}")
            try:
                rt.run([{"op": "code", "name": f"{name}_batch", "asm": "\n".join(head + body), "auto_ret": False},
                        {"op": "call", "rip": f"@{name}_batch", "args": [], "store": "ret"}])
                ok += len(chunk)
                for j, (n, _v) in enumerate(chunk):
                    progress(start + j + 1, n, None)
            except Exception as exc:
                failed += len(chunk)
                log(f"  batch FAILED (not retried - some of these items may have been added): {exc}")
                progress(start + len(chunk), chunk[-1][0], str(exc))
                if stop_on_error or not app.client.connected:
                    break
            if delay_ms and start + batch < total:
                if cancel is not None and cancel.wait(delay_ms / 1000.0):
                    cancelled = True
                    break
        return ok, failed, cancelled

    def _after_run(self, game: Game, cheat: Cheat, rax: int, off: bool,
                   on_done: Optional[Callable[[bool], None]]) -> None:
        app = self.app
        app._refresh_buf_tree()
        app.rax_var.set(f"RAX = 0x{rax:X}")
        app.log_line(f"done: {cheat.name} ({'off' if off else 'ok'})")
        self._notify_state()
        if on_done:
            on_done(off)

    def find_process(self, game: Game) -> None:
        app = self.app
        if not game.title_id and not game.process:
            from tkinter import messagebox
            messagebox.showerror("Cheats", "Game has no title_id or process set")
            return
        root = app.root

        def work() -> None:
            found = None
            for p in app.client.list_processes():
                if game.process and p.name.lower() == game.process.lower() and not game.title_id:
                    found = p
                    break
                try:
                    info = app.client.proc_info(p.pid)
                except Exception:
                    continue
                if game.title_id and info.titleid.strip().upper() == game.title_id.upper():
                    found = p
                    break
            if not found:
                raise RuntimeError(f"{game.name} ({game.title_id}) is not running")
            root.after(0, lambda: (app.pid_var.set(str(found.pid)),
                                   app.log_line(f"found {game.name}: pid={found.pid} ({found.name})")))

        app._run_bg(work, "Searching processes...")
