"""Helpers that let the Cheat Editor write the JSON for you.

* caller_to_steps():  turns the Caller tab (RIP, args, @buffers, quick-code) into
  steps - including an `alloc` (with the buffer's current contents) or `code`
  step for every @buffer the call uses, directly or through its assembly.
* check_cheat():      finds @buffers a cheat uses before any step creates them.
* add_steps():        merges new steps into a cheat (replaces same-name alloc/code).
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional

from cheat_recorder import _placeholder_text

REF = re.compile(r"@([A-Za-z_][\w.]*)")
DEFINES = ("alloc", "code", "hook")
KIND_TYPE = {"u64 / pointer": "u64", "i64": "i64", "u32": "u32", "i32": "i32",
             "float bits": "f32", "double bits": "f64"}


def _strings(obj: Any, skip_keys: tuple = ()) -> list[str]:
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k not in skip_keys:
                out += _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _strings(v)
    return out


PY_DEFINES = re.compile(r"""\b(?:ps5|game)\.(?:alloc|code)\(\s*["']([\w.\-]+)["']""")


def refs_of_step(step: dict) -> set[str]:
    """@names a step reads (the name it creates is not a reference)."""
    if not isinstance(step, dict):
        return set()
    op = str(step.get("op", "")).lower()
    skip = ("name", "op", "steps") if op in DEFINES + ("free",) else ("op", "steps")
    names = set()
    for s in _strings(step, skip):
        for line in s.split("\n"):
            names.update(REF.findall(line.split(";", 1)[0]))
    return names


def check_cheat(steps: list) -> list[str]:
    """Names used before any step creates them (in run order)."""
    created: set[str] = set()
    missing: list[str] = []

    def walk(lst: list) -> None:
        for st in lst:
            if not isinstance(st, dict):
                continue
            op = str(st.get("op", "")).lower()
            if op == "repeat":
                walk(st.get("steps", []))
                continue
            if op == "python":                     # ps5.alloc("x") / ps5.code("x") create @x
                created.update(PY_DEFINES.findall(str(st.get("code", ""))))
                continue
            for n in sorted(refs_of_step(st)):
                if n not in created and n not in missing:
                    missing.append(n)
            if op in DEFINES and st.get("name"):
                created.add(str(st["name"]))

    walk(steps)
    return missing


def add_steps(cheat: dict, new_steps: list[dict], front: bool = False) -> list[str]:
    """Merge steps into cheat["steps"].  An alloc/code step whose name already exists
    replaces that step in place; others are appended (or put first when `front`)."""
    steps = cheat.setdefault("steps", [])
    log: list[str] = []
    head: list[dict] = []
    for st in new_steps:
        op = str(st.get("op", "")).lower()
        if op in ("alloc", "code") and st.get("name"):
            i = next((k for k, x in enumerate(steps) if isinstance(x, dict)
                      and str(x.get("op", "")).lower() in ("alloc", "code") and x.get("name") == st["name"]), None)
            if i is not None:
                steps[i] = st
                log.append(f"updated {op} @{st['name']}")
                continue
        (head if front else steps).append(st)
        log.append(f"added {op}" + (f" @{st['name']}" if st.get("name") else ""))
    if head:
        steps[:0] = head
    return log


def buffer_step(app, name: str, read: Callable[[int, int], bytes]) -> Optional[dict]:
    """alloc/code step that recreates session buffer @name (None if unknown)."""
    buf = next((b for b in app.state.buffers if b.name == name), None)
    if buf is None:
        return None
    src = getattr(app, "code_sources", {}).get(name)
    if src is not None:
        st: dict = {"op": "code", "name": name, "asm": src["asm"].rstrip("\n")}
        if src.get("prot") not in (None, "rx"):
            st["prot"] = src["prot"]
        if src.get("auto_ret") is False:
            st["auto_ret"] = False
        if src.get("auto_frame") is False:
            st["auto_frame"] = False
        return st
    st = {"op": "alloc", "name": name, "size": buf.size}
    data = b""
    if buf.size <= 0x10000:
        try:
            data = read(buf.address, buf.size)
        except Exception:
            data = b""
    if data and any(data):
        text = _placeholder_text(data)
        if text is not None:
            st["init"] = {"type": text[0], "value": text[1]}
        else:
            end = len(data.rstrip(b"\0"))
            end = (end + 3) & ~3 if end else 0
            st["init"] = {"type": "hex", "value": data[:end].hex(" "), "nul": False}
    return st


def dependency_steps(app, names: set[str], read: Callable[[int, int], bytes],
                     have: set[str]) -> tuple[list[dict], list[str], list[dict]]:
    """Steps (allocs first, then code) for @names and everything their code uses.
    -> (steps, names that are not in this session, `set` steps for quick-code variables)"""
    order: list[str] = []
    unknown: list[str] = []
    sets: list[dict] = []
    seen: set[str] = set()
    sources = getattr(app, "code_sources", {})

    def visit(n: str) -> None:
        if n in seen:
            return
        seen.add(n)
        src = sources.get(n)
        if src is not None:
            for line in src.get("asm", "").split("\n"):
                for m in REF.findall(line.split(";", 1)[0]):
                    visit(m)
            for vname, (expr, _val) in src.get("vars", {}).items():
                for m in REF.findall(str(expr)):
                    visit(m)
                sets.append({"op": "set", "var": vname, "value": str(expr)})
        order.append(n)

    for n in sorted(names):
        visit(n)
    allocs, codes = [], []
    for n in order:
        if n in have:
            continue
        st = buffer_step(app, n, read)
        if st is None:
            unknown.append(n)
        elif st["op"] == "code":
            codes.append(st)
        else:
            allocs.append(st)
    return allocs + codes, unknown, sets


def caller_to_steps(app, read: Callable[[int, int], bytes], have: set[str],
                    existing_params: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    """The Caller tab as steps: [allocs/code for used @buffers] + [set vars] + call.
    'edit'-ticked registers become inputs ($params).  -> (steps, new params, notes)"""
    regs = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    params: list[dict] = []
    taken = {p.get("name") for p in existing_params}
    args: list[Any] = []
    texts = [app.rip_var.get().strip()]
    for reg in regs:
        kind = app.arg_kind[reg].get()
        val = app.arg_val[reg].get().strip() or "0"
        texts.append(val)
        if app.arg_edit[reg].get():
            picked = app.arg_item_pick.get(reg)
            lst = picked[0] if picked else ""
            base = "item" if lst else f"value_{reg}"
            name, k = base, 2
            while name in taken:
                name, k = f"{base}{k}", k + 1
            taken.add(name)
            ptype = KIND_TYPE.get(kind, "u64")
            default = picked[1] if picked else val
            p = {"name": name, "label": name.replace("_", " ").title(), "type": ptype, "default": default}
            if lst:
                p["items"] = lst
            params.append(p)
            args.append(f"${name}" if ptype in ("u64",) else {"type": ptype, "value": f"${name}"})
        elif kind == "float bits":
            args.append({"type": "f32", "value": float(val)})
        elif kind == "double bits":
            args.append({"type": "f64", "value": float(val)})
        elif kind in ("u32", "i32"):
            args.append({"type": kind, "value": val})
        else:
            args.append(val)
    while args and args[-1] in ("0", 0):
        args.pop()
    used: set[str] = set()
    for t in texts:
        used.update(REF.findall(t))
    deps, unknown, sets = dependency_steps(app, used, read, have)
    have_vars = {p.get("name") for p in existing_params} | {p["name"] for p in params}
    sets = [s for s in sets if s["var"] not in have_vars]
    call = {"op": "call", "rip": texts[0] or "0", "args": args, "store": "ret"}
    notes = [f"@{n} is not a buffer in this session - create it in the Caller tab first" for n in unknown]
    return deps + sets + [call], params, notes
