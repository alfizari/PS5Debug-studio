"""ShnExt (Reaper Studio) patches <-> this tool's cheat steps.

A ShnExt patch (one cheat) is a list of labelled variables.  Learned from 589 real trainers
(5,633 patches) of the Reaper Software Suite repository and the author's own projects:

  type 11 + offsetFinder        a code SITE found by an AOB (sectionId, UniqueAOB, Mask; ptr is 0).
                                 defaultValue = original code, newValue = replacement (or None)
  type 11 + baseId "0" / "N"    a SITE at a fixed offset from the executable / its section N
  type 11 + baseId <label>      a SITE at <label> + offset
  type 11, baseId ""/None       a CAVE block.  All blocks of a patch are one code cave, laid out in
                                 variable order (a block may fall through into the next one);
                                 each label is the address of its block
  type 6  + baseId <label>      an ADDRESS = <label> + offset (e.g. the return point of a hook)
  types 1-8, 10, 12             DATA, each a small buffer:
                                 1 byte, 4 2 bytes, 2/5 4 bytes, 3/6 8 bytes, 7 float, 8 double,
                                 10 hex bytes (defaultValue / newValue), 12 bytes chosen from an
                                 item dictionary (option {"Label", "items": {name: hex bytes}})
                                 with editor -> an input on the Cheats tab
In the assembly text a label means its address; [label] / [label+8] reads memory there.
A site whose new code is "jmp <cave label>" (+ nops) is a hook.
"""

from __future__ import annotations

import base64
import json
import re
import struct
from typing import Callable, Optional

import aob as aobmod

DATA_TYPES = {1: ("u8", 1), 4: ("u16", 2), 2: ("u32", 4), 5: ("u32", 4), 3: ("u64", 8), 6: ("u64", 8),
              7: ("f32", 4), 8: ("f64", 8)}
EXPORT_TYPE = {"u8": 1, "i8": 1, "u16": 4, "i16": 4, "u32": 2, "i32": 2, "u64": 6, "i64": 6, "ptr": 6,
               "f32": 7, "f64": 8}
_IDENT_RE = re.compile(r"[A-Za-z_]\w*$")


class ShnExtError(Exception):
    pass


# ------------------------------------------------------------------ helpers
def _crlf_free(t) -> str:
    return str(t or "").replace("\r", "")


def _hex_or_b64(text: str) -> bytes:
    """type 10/12 values: '20', '00-00-00', '0000803F' (hex) or 'AAAAAA==' (base64)"""
    t = str(text or "").strip()
    h = t.replace("-", "").replace(" ", "")
    if h and re.fullmatch(r"[0-9A-Fa-f]+", h) and len(h) % 2 == 0:
        return bytes.fromhex(h)
    try:
        return base64.b64decode(t, validate=True) if t else b""
    except Exception:
        raise ShnExtError(f"value '{t}' is neither hex nor base64") from None


def _nop_count(text: str) -> Optional[int]:
    m = re.fullmatch(r"nop\s*:\s*(\d+)", text.strip(), flags=re.IGNORECASE)
    return int(m.group(1)) if m else None


class _Names:
    """ShnExt labels -> names usable as $var / @buffer / asm labels (kept when already valid)."""

    def __init__(self) -> None:
        self.map: dict[str, str] = {}
        self.used: set[str] = set()

    def get(self, label: str) -> str:
        if label in self.map:
            return self.map[label]
        n = label if _IDENT_RE.match(label) and label != "ret" else "v_" + (re.sub(r"\W", "_", label).strip("_") or "x")
        base, k = n, 2
        while n in self.used:
            n, k = f"{base}_{k}", k + 1
        self.map[label] = n
        self.used.add(n)
        return n


def _label_re(label: str) -> re.Pattern:
    return re.compile(r"(?<![\w.$@])" + re.escape(label) + r"(?![\w])")


# ------------------------------------------------------------------ import
def _clean_asm(text: str) -> str:
    """Reaper assembly quirks -> keystone: // comments, "nop:N" lines, "dword [x]" without ptr"""
    out = []
    for line in _crlf_free(text).split("\n"):
        line = line.split("//", 1)[0]
        n = _nop_count(line)
        if n is not None and 0 < n <= 4096:
            out += ["nop"] * n
            continue
        out.append(re.sub(r"\b(byte|word|dword|qword|xmmword|ymmword)\s+\[", r"\1 ptr [", line, flags=re.IGNORECASE))
    return "\n".join(out)


def project_labels(patches: list[dict]) -> dict[str, tuple[str, str]]:
    """every label of a project -> (patch name, kind).  Patches may use another patch's variables."""
    out: dict[str, tuple[str, str]] = {}
    for p in patches:
        for v in p.get("Variables", []) or []:
            lbl = v.get("label")
            if lbl and lbl not in out:
                t = v.get("type")
                kind = "data" if (t in DATA_TYPES or t in (10, 12)) and v.get("baseId") in ("", None) else "other"
                out[str(lbl)] = (str(p.get("name") or "patch"), kind)
    return out


_REGS = frozenset(
    [f"r{r}" for r in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")]
    + [f"e{r}" for r in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")]
    + ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]
    + [f"r{n}{x}" for n in range(8, 16) for x in ("", "d", "w")])


def reap_to_cheat(p: dict, notes: list[str], items_out: Optional[dict] = None,
                  project: Optional[dict] = None) -> dict:
    """One decrypted ShnExt patch -> one toggle cheat of this tool.  project = project_labels(...)"""
    name = str(p.get("name") or "patch")
    vars_: dict[str, dict] = {}
    for v in p.get("Variables", []) or []:
        if v.get("label"):
            vars_[str(v["label"])] = v                   # dict semantics: first position, last value
    nm = _Names()
    kinds: dict[str, str] = {}
    for lbl, v in vars_.items():
        t, base = v.get("type"), v.get("baseId")
        if t == 11:
            if v.get("offsetFinder"):
                kinds[lbl] = "aob"
            elif base not in ("", None):
                kinds[lbl] = "site"                      # base "N" = section N, or another label
            else:
                kinds[lbl] = "cave"
        elif t == 6 and base not in ("", None):
            kinds[lbl] = "addr"
        elif t in DATA_TYPES or t in (10, 12):
            kinds[lbl] = "data" if base in ("", None) else "unknown"
        else:
            kinds[lbl] = "unknown"
    for lbl in vars_:
        nm.get(lbl)
    unsupported: list[str] = [f"variable '{l}' (type {vars_[l].get('type')}, base '{vars_[l].get('baseId')}')"
                              for l, k in kinds.items() if k == "unknown"]
    # data of other patches of the same project: a buffer that patch creates (it must be on first)
    foreign = {l: pn for l, (pn, k) in (project or {}).items() if k == "data" and l not in vars_}
    for l in foreign:
        kinds[l] = "data"
        nm.get(l)
    used_foreign: set[str] = set()
    labels_by_len = sorted(list(vars_) + list(foreign), key=len, reverse=True)

    def translate(text: str, block: Optional[str] = None) -> str:
        """Reaper assembly -> this tool's: [data] -> [rip:@data], data -> @data, site/address -> $name,
        cave labels stay assembly labels; a block's own inline labels get unique names."""
        t = _clean_asm(text)
        ph: dict[str, str] = {}
        for lbl in labels_by_len:
            tok = f"\x00{len(ph)}\x00"
            new = _label_re(lbl).sub(tok, t)
            if new != t:
                ph[tok] = lbl
                t = new
                if lbl in foreign:
                    used_foreign.add(lbl)

        def bracket(m: re.Match) -> str:
            inner = m.group(1)
            toks = re.findall(r"\x00\d+\x00", inner)
            if not toks:
                return m.group(0)
            if len(toks) > 1:
                unsupported.append(f"'{inner}' uses two labels in one operand")
                return m.group(0)
            lbl = ph[toks[0]]
            rest = inner.replace(toks[0], "").replace(" ", "")
            if kinds[lbl] == "cave" or (rest and not re.fullmatch(r"[+-](0x[0-9A-Fa-f]+|\d+)", rest)):
                unsupported.append(f"'[{inner.replace(toks[0], lbl)}]' is not [label] or [label+offset]")
                return m.group(0)
            ref = ("@" if kinds[lbl] == "data" else "$") + nm.get(lbl)
            return f"[rip:{ref}{rest}]"

        t = re.sub(r"\[([^\]]*)\]", bracket, t)
        # movabs only takes a 64-bit absolute address; with a [label] it means an ordinary load/store
        t = re.sub(r"\bmovabs\b(?=[^\n]*\[rip:)", "mov", t, flags=re.IGNORECASE)
        for tok, lbl in ph.items():
            k = kinds[lbl]
            t = t.replace(tok, nm.get(lbl) if k == "cave" else ("@" if k == "data" else "$") + nm.get(lbl))
        if block is not None:                             # inline labels of this block: unique names
            own = re.findall(r"^\s*([@A-Za-z_.][\w.]*)\s*:", t, flags=re.MULTILINE)
            for il in sorted(set(own), key=len, reverse=True):
                if "__il_" in il:
                    continue                              # already unique (written by this tool)
                new = f"{block}__il_{re.sub(r'\W', '_', il).strip('_')}"
                t = re.sub(r"(?<![\w.$])" + re.escape(il) + r"(?![\w])", new, t)
        return "\n".join(line.rstrip() for line in t.split("\n")).strip()

    steps: list[dict] = []
    params: list[dict] = []
    first_site: Optional[str] = None

    # 1. AOB sites
    for lbl, v in vars_.items():
        if kinds[lbl] != "aob":
            continue
        f = v["offsetFinder"]
        pat, mask = aobmod.from_b64(f.get("UniqueAOB", ""), f.get("Mask"))
        st = {"op": "aob", "pattern": aobmod.fmt(pat, mask), "store": nm.get(lbl)}
        sec = int(f.get("sectionId") or 0)
        if sec:
            st["module"] = f"main#{sec}"
            st["data"] = True
        if int(v.get("offset") or 0):
            st["offset"] = int(v["offset"])
        if int(f.get("ptr") or 0) or v.get("offsetFinderPtr"):
            unsupported.append(f"'{lbl}' uses a pointer offset finder")
        steps.append(st)
        first_site = first_site or nm.get(lbl)

    # 2. sites and addresses computed from other labels (in dependency order)
    pending = [l for l, k in kinds.items() if k in ("site", "addr")]
    done = {l for l, k in kinds.items() if k == "aob"}
    while pending:
        progress = False
        for lbl in list(pending):
            v = vars_[lbl]
            base, off = str(v.get("baseId")), int(v.get("offset") or 0)
            if base.isdigit() and base not in vars_:     # section number
                expr = f"module(main)+0x{off:X}" if int(base) == 0 else f"module(main#{int(base)})+0x{off:X}"
            elif base in vars_ and base in done:
                expr = f"${nm.get(base)}" + (f"+0x{off:X}" if off else "")
            elif base in vars_ and kinds.get(base) in ("site", "addr"):
                continue                                   # its base is not set yet
            else:
                unsupported.append(f"'{lbl}' is based on '{base}', which is not an address")
                pending.remove(lbl)
                progress = True
                continue
            steps.append({"op": "set", "var": nm.get(lbl), "value": expr})
            first_site = first_site or (nm.get(lbl) if kinds[lbl] == "site" else None)
            done.add(lbl)
            pending.remove(lbl)
            progress = True
        if not progress:
            unsupported.append("addresses based on each other in a loop: " + ", ".join(pending))
            break

    # 3. data variables -> buffers (inputs when they have an editor)
    for lbl, v in vars_.items():
        if kinds[lbl] != "data":
            continue
        t = v.get("type")
        val = v.get("newValue") if v.get("newValue") is not None else v.get("defaultValue")
        bname = nm.get(lbl)
        st: dict = {"op": "alloc", "name": bname, "prot": "rw"}
        if first_site:
            st["near"] = f"${first_site}"
        if t in DATA_TYPES:
            typ, size = DATA_TYPES[t]
            if EXPORT_TYPE.get(typ) != t:
                st["shnext_type"] = t                     # the same size under another type number
            sval = str(val if val is not None else 0)
            if typ in ("f32", "f64"):
                sval = repr(float(val or 0))
            else:
                try:
                    sval = str(int(float(val or 0)))
                except (TypeError, ValueError):
                    unsupported.append(f"'{lbl}' value {val!r} is not a number")
            st["size"] = 16
            if v.get("editor") is not None:
                params.append({"name": bname, "label": str(v.get("DisplayName") or lbl), "type": typ, "default": sval})
                st["init"] = {"type": typ, "value": f"${bname}"}
            else:
                st["init"] = {"type": typ, "value": sval}
        else:                                              # 10 / 12: bytes
            try:
                raw = _hex_or_b64(val if val is not None else "")
            except ShnExtError as exc:
                unsupported.append(f"'{lbl}': {exc}")
                raw = b""
            st["size"] = max(16, (len(raw) + 15) & ~15)
            opt = v.get("option") or {}
            if t == 12 and isinstance(opt, dict) and opt.get("items") and len(raw) in (1, 2, 4, 8):
                ptype = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}[len(raw)]
                lst = str(opt.get("Label") or lbl)
                ids = {}
                for item, hx in opt["items"].items():
                    try:
                        b = _hex_or_b64(hx)
                        ids[str(item)] = int.from_bytes(b[:len(raw)].ljust(len(raw), b"\0"), "little")
                    except ShnExtError:
                        continue
                if items_out is not None:
                    items_out.setdefault(lst, {}).update(ids)
                params.append({"name": bname, "label": str(v.get("DisplayName") or lbl), "type": ptype,
                               "default": str(int.from_bytes(raw, "little")), "items": lst})
                st["init"] = {"type": ptype, "value": f"${bname}"}
            elif raw:
                st["init"] = {"type": "hex", "value": raw.hex(" ").upper()}
        steps.append(st)

    # 4. the cave: every block in variable order, each one starting with its label
    blocks = [l for l in vars_ if kinds[l] == "cave"]
    block_text = {l: translate(vars_[l].get("defaultValue") or "", block=nm.get(l)) for l in blocks}

    def cave_from(label: str) -> str:
        i = blocks.index(label)
        order = blocks[i:] + blocks[:i]                   # starts at the hook target, keeps fall-through
        return "\n".join(f"{nm.get(b)}:\n{block_text[b]}" if block_text[b] else f"{nm.get(b)}:" for b in order)

    # 5. what the sites become: hooks, nop patches, assembly patches
    patch_steps: list[dict] = []
    hooked: set[str] = set()
    for lbl, v in vars_.items():
        if kinds[lbl] not in ("aob", "site"):
            continue
        new = _crlf_free(v.get("newValue")).strip()
        if not new:
            continue
        site = f"${nm.get(lbl)}"
        orig_text = _crlf_free(v.get("defaultValue")).strip()       # the game's code, as the author wrote it
        n = _nop_count(new)
        if n is not None:
            if not 0 < n <= 4096:
                notes.append(f"{name}: '{lbl}' has a bad nop count ({new})")
                continue
            st = {"op": "patch", "addr": site, "type": "hex", "value": " ".join(["90"] * n)}
            if orig_text:
                st["shnext_orig"] = orig_text
            patch_steps.append(st)
            continue
        m = re.fullmatch(r"jmp\s+(.+?)((?:\s*\n\s*nop)*)\s*", new, flags=re.IGNORECASE)
        target = m.group(1).strip() if m else None
        if target in vars_ and kinds[target] == "cave":
            import asmgen
            length = 5 + len(re.findall(r"\bnop\b", m.group(2), flags=re.IGNORECASE))
            orig_hex = ""
            if kinds[lbl] == "aob":
                pat, mask = aobmod.from_b64(v["offsetFinder"].get("UniqueAOB", ""), v["offsetFinder"].get("Mask"))
                off = int(v.get("offset") or 0)
                if 0 <= off and len(pat) >= off + length and all(mask[off:off + length]):
                    orig_hex = pat[off:off + length].hex(" ").upper()
            if not orig_hex:
                try:
                    b = asmgen.assemble(_crlf_free(v.get("defaultValue")), 0)
                    if len(b) == length:
                        orig_hex = b.hex(" ").upper()
                except Exception:
                    pass
            hname = nm.get(target) if nm.get(target) not in hooked else f"{nm.get(target)}_{nm.get(lbl)}"
            st = {"op": "hook", "name": hname, "addr": site, "asm": cave_from(target)}
            if orig_hex:
                st["orig"] = orig_hex
            else:
                st["orig"], st["length"] = "auto", length
            if orig_text:
                st["shnext_orig"] = orig_text
            patch_steps.append(st)
            hooked.add(hname)
            continue
        jm = re.match(r"\s*(?:jmp|call)\s+([A-Za-z_.@][\w.@ ]*?)\s*(?:\n|$)", _crlf_free(new), flags=re.IGNORECASE)
        if jm and jm.group(1) not in vars_ and jm.group(1) not in foreign and not re.fullmatch(r"\d+|0x[0-9A-Fa-f]+", jm.group(1)) \
                and jm.group(1).lower() not in _REGS:
            unsupported.append(f"'{lbl}' jumps to '{jm.group(1)}', which this patch does not define")
            continue
        st = {"op": "asmpatch", "addr": site, "asm": translate(new)}
        if orig_text:
            st["shnext_orig"] = orig_text
        patch_steps.append(st)
    steps += patch_steps

    cheat = {"name": name, "mode": "toggle", "steps": steps}
    if params:
        cheat["params"] = params
    if p.get("info"):
        cheat["description"] = _crlf_free(p["info"])
    if p.get("author"):
        cheat["author"] = str(p["author"])
    if p.get("isMasterCode") and not re.search(r"master\s*code", name, re.IGNORECASE):
        cheat["name"] = f"{name} (master code)"
    if used_foreign:
        needs = sorted({foreign[l] for l in used_foreign})
        cheat["description"] = (cheat.get("description", "") + ("\n" if cheat.get("description") else "")
                                + "Uses values of: " + ", ".join(needs) + " - turn that on first.")
    renamed = {new: old for old, new in nm.map.items() if new != old}
    if renamed:                                       # so the export writes the project's own label names
        for st in steps:
            text = json.dumps(st)
            used = {n: o for n, o in renamed.items() if re.search(r"(?<![\w.])" + re.escape(n) + r"(?!\w)", text)}
            if used:
                st["shnext_labels"] = used
    if unsupported:
        cheat["shnext_unsupported"] = sorted(set(unsupported))
        notes.append(f"{name}: " + "; ".join(sorted(set(unsupported))[:3]))
    return cheat


# ------------------------------------------------------------------ export
def _to_reaper_asm(asm: str, names: set[str], errors: list[str], where: str, inputs: frozenset = frozenset()) -> str:
    """this tool's assembly -> Reaper's: [rip:@x+8] -> [x+8], @x / $x -> x"""
    t = str(asm).replace("\r", "")
    if re.search(r"\{[^}]*\}", t):
        errors.append(f"{where}: {{expressions}} cannot be written into a ShnExt")
    if "module(" in t:
        errors.append(f"{where}: module(...) addresses cannot be written into a ShnExt - use a label")
    t = re.sub(r"\[rip:\s*[@$]([A-Za-z_]\w*)\s*([^\]]*)\]", lambda m: f"[{m.group(1)}{m.group(2).replace(' ', '')}]", t)

    def bare(m: re.Match) -> str:
        n = m.group(1)
        if n == "ret":
            errors.append(f"{where}: $ret (the last call's result) has no ShnExt equivalent")
        elif n in inputs and n not in names:
            errors.append(f"{where}: input ${n} is used directly in the code - ShnExt inputs live in memory: "
                          f"store it in a buffer (alloc with start value ${n}) and read [buffer]")
        elif n not in names:
            errors.append(f"{where}: {m.group(0)} is not a variable, buffer or label of this cheat")
        return n
    t = re.sub(r"[@$]([A-Za-z_]\w*)", bare, t)
    return t.replace("\n", "\r\n")


_MAX_OFF = 1 << 53


def _same_type(step: dict, t: int) -> int:
    """keep the project's own type number when it means the same thing (5 = u32, 3 = u64)"""
    o = step.get("shnext_type")
    return o if isinstance(o, int) and o in DATA_TYPES and DATA_TYPES[o] == DATA_TYPES[t] else t


def cheat_to_reap(cheat, index: int, author: str, items: Optional[dict] = None,
                  read_orig: Optional[Callable[[str, int], bytes]] = None,
                  process: str = "eboot.bin") -> tuple[Optional[dict], list[str]]:
    """One cheat of this tool -> (ShnExt patch dict, errors).  read_orig(addr_expr, n) gives the game's
    original bytes for fixed-offset sites (None = not available)."""
    import cheat_export as ce

    errors: list[str] = []
    steps = list(cheat.steps)
    params = {p["name"]: p for p in (cheat.params or []) if isinstance(p, dict)}
    if cheat.mode == "once":
        errors.append("is a run-once cheat - ShnExt cheats are on/off")
    # off steps that write back bytes at addresses the cheat patches = the original code (ShnExt's
    # defaultValue); anything else cannot be expressed - ShnExt only restores the original code
    off_bytes: dict[str, bytes] = {}
    on_addrs = {str(s.get("addr")) for s in steps if str(s.get("op", "")).lower() in ("write", "patch", "asmpatch")}
    for s in cheat.off or []:
        if (str(s.get("op", "")).lower() == "write" and str(s.get("type", "")).lower() in ("hex", "bytes")
                and str(s.get("addr")) in on_addrs):
            off_bytes[str(s["addr"])] = bytes.fromhex(re.sub(r"\s+", "", str(s["value"])))
        else:
            errors.append("has 'off' steps that do more than put the original bytes back - "
                          "ShnExt can only restore the original code")
            break
    variables: list[dict] = []
    by_label: dict[str, dict] = {}
    names: set[str] = set()

    def var(label: str, **kw) -> dict:
        v = {"index": 0, "defaultValue": None, "newValue": None, "type": 11, "editor": None,
             "isAlwaysEnabled": False, "isStatic": False, "offsetFinder": None, "offsetFinderPtr": None,
             "option": None, "label": label, "DisplayName": None, "comment": None, "baseId": "", "offset": 0}
        v.update(kw)
        variables.append(v)
        by_label[label] = v
        names.add(label)
        return v

    # names first: every buffer / variable / hook can be referenced from any code
    for s in steps:
        op = str(s.get("op", "")).lower()
        if op == "aob":
            names.add(str(s.get("store", "aob")))
        elif op in ("set", "alloc", "code", "hook"):
            names.add(str(s.get("var") if op == "set" else s.get("name")))
    for s in steps:
        if str(s.get("op", "")).lower() == "hook":
            names.add(f"{s.get('name')}Return")

    def site_for(addr: str, fallback_label: str) -> Optional[dict]:
        """the site variable at addr ($var, $var+0xN, module(main)+0xN)"""
        a = str(addr).replace(" ", "")
        m = re.fullmatch(r"\$([A-Za-z_]\w*)(?:\+0x([0-9A-Fa-f]+))?", a)
        if m and not m.group(2) and m.group(1) in by_label:
            return by_label[m.group(1)]
        if m:
            if m.group(1) not in by_label:
                errors.append(f"site {addr}: ${m.group(1)} is not an AOB result or address of this cheat")
                return None
            return var(fallback_label, baseId=m.group(1), offset=int(m.group(2) or "0", 16))
        try:
            sec, off = ce._addr((ce._StaticRT(ce._B1, process), ce._StaticRT(ce._B2, process)), a)
        except Exception as exc:
            errors.append(f"site {addr}: {exc}")
            return None
        if sec < 0:
            errors.append(f"site {addr}: an absolute address cannot be written into a ShnExt")
            return None
        if off >= _MAX_OFF:
            errors.append(f"site {addr}: offset 0x{off:X} is negative or too large for a ShnExt "
                          "(offsets are stored as JSON numbers)")
            return None
        return var(fallback_label, baseId=str(sec), offset=off, isStatic=True)

    def original(site: dict, addr: str, n: int, kept: str = "") -> Optional[bytes]:
        if kept:
            return None                                   # the step carries the original code as text
        if addr in off_bytes:
            return off_bytes[addr]
        f = site.get("offsetFinder")
        if f:
            pat, mask = aobmod.from_b64(f["UniqueAOB"], f["Mask"])
            off = int(site.get("offset") or 0)
            if len(pat) >= off + n and all(mask[off:off + n]):
                return pat[off:off + n]
            errors.append(f"{site['label']}: the AOB has wildcards over the patched bytes, so the original code "
                          "is unknown - make those bytes fixed in the AOB")
            return None
        if read_orig is None:
            errors.append(f"{site['label']}: needs the game's original bytes - press 'Read original bytes'")
            return None
        b = read_orig(addr, n)
        if b is None:
            errors.append(f"{site['label']}: needs the game's original bytes - press 'Read original bytes'")
            return None
        if len(b) != n:
            errors.append(f"{site['label']}: could not read the original bytes")
            return None
        return b

    inputs = frozenset(params)

    def asm(text: str, where: str) -> str:
        return _to_reaper_asm(text, names, errors, where, inputs)

    hooks = 0
    for i, s in enumerate(steps):
        op = str(s.get("op", "")).lower()
        where = f"step {i + 1} ({op})"
        if op in ("log", "sleep"):
            continue
        if s.get("alt"):
            errors.append(f"{where}: a Section N line from a .shn/.json file - tools disagree on what Section N "
                          "means, so it is not written into a ShnExt")
            continue
        if s.get("mc"):
            errors.append(f"{where}: a Master Code dependent line (found inside the Master Code's code) "
                          "has no ShnExt equivalent")
            continue
        if op == "aob":
            toks = str(s["pattern"]).replace(",", " ").replace("-", " ").split()
            if len(toks) == 1 and len(toks[0]) > 2:
                toks = [toks[0][k:k + 2] for k in range(0, len(toks[0]), 2)]
            try:
                pat = bytes(0 if set(t) <= {"?", "*"} else int(t, 16) for t in toks)
                mask = bytes(0 if set(t) <= {"?", "*"} else 1 for t in toks)
            except ValueError:
                errors.append(f"{where}: bad AOB pattern")
                continue
            mod = str(s.get("module", "main"))
            sec = 0
            if "#" in mod:
                sec = int(mod.split("#", 1)[1] or 0)
            elif mod.lower() not in ("main", "eboot.bin", ""):
                errors.append(f"{where}: ShnExt AOBs search the game executable only (not {mod})")
            var(str(s.get("store", "aob")), baseId="0", offset=int(s.get("offset", 0) or 0),
                offsetFinder={"sectionId": sec, "UniqueAOB": base64.b64encode(pat).decode(),
                              "Mask": base64.b64encode(mask).decode(), "ptr": 0})
        elif op == "set":
            m = re.fullmatch(r"\$([A-Za-z_]\w*)(?:\+0x([0-9A-Fa-f]+))?", str(s.get("value", "")).replace(" ", ""))
            m2 = re.fullmatch(r"module\((?:main|eboot\.bin)(?:#(\d+))?\)\+0x([0-9A-Fa-f]+)", str(s.get("value", "")).replace(" ", ""))
            if m and m.group(1) in by_label:
                var(str(s["var"]), type=6, defaultValue=0, baseId=m.group(1), offset=int(m.group(2) or "0", 16))
            elif m2 and int(m2.group(2), 16) >= _MAX_OFF:
                errors.append(f"{where}: offset 0x{m2.group(2)} is negative or too large for a ShnExt")
            elif m2:
                var(str(s["var"]), baseId=str(int(m2.group(1) or 0)), offset=int(m2.group(2), 16), isStatic=True)
            else:
                errors.append(f"{where}: ${s.get('var')} = {s.get('value')} - ShnExt addresses are label + offset")
        elif op == "alloc":
            init = s.get("init") or {}
            typ = str(init.get("type", "")).lower()
            val = init.get("value", "")
            p = params.get(str(val)[1:]) if isinstance(val, str) and val.startswith("$") else None
            if p:
                ptype = str(p.get("type", "u64")).lower()
                if p.get("items"):
                    lst = items.get(p["items"], {}) if items else {}
                    size = {"u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4}.get(ptype, 8)
                    if not lst:
                        errors.append(f"{where}: item list '{p['items']}' is not loaded")
                    var(str(s["name"]), type=12, editor={"editType": 1, "varType": 10},
                        defaultValue=base64.b64encode(int(p.get("default") or 0).to_bytes(size, "little", signed=False)).decode(),
                        option={"Label": p["items"], "items": {k: (int(v) & ((1 << (8 * size)) - 1)).to_bytes(size, "little").hex().upper()
                                                                for k, v in lst.items()}},
                        DisplayName=(p.get("label") if p.get("label") != s["name"] else None))
                elif ptype in EXPORT_TYPE:
                    t = EXPORT_TYPE[ptype]
                    t = _same_type(s, t)
                    dv = float(p.get("default") or 0) if t in (7, 8) else int(str(p.get("default") or 0), 0)
                    var(str(s["name"]), type=t, editor={"editType": 1, "varType": t}, defaultValue=dv,
                        DisplayName=(p.get("label") if p.get("label") != s["name"] else None))
                else:
                    errors.append(f"{where}: input type {ptype} has no ShnExt equivalent")
            elif typ in EXPORT_TYPE:
                t = EXPORT_TYPE[typ]
                t = _same_type(s, t)
                try:
                    dv = float(val) if t in (7, 8) else int(str(val), 0)
                except (TypeError, ValueError):
                    errors.append(f"{where}: start value {val!r} must be a number")
                    dv = 0
                var(str(s["name"]), type=t, defaultValue=dv)
            elif typ in ("hex", "bytes"):
                var(str(s["name"]), type=10, defaultValue=re.sub(r"\s+", "", str(val)).upper())
            elif not typ:
                var(str(s["name"]), type=10, defaultValue="00" * int(str(s.get("size", 8)), 0))
            else:
                errors.append(f"{where}: buffers with {typ} text cannot be written into a ShnExt")
        elif op == "code":
            var(str(s["name"]), defaultValue=asm(s.get("asm", ""), where) + "\r\n")
        elif op == "hook":
            if s.get("far"):
                errors.append(f"{where}: far (14-byte) hooks have no ShnExt equivalent - use a normal hook")
            name = str(s.get("name") or f"hook{i}")
            orig = None
            n = int(s.get("length", 5)) if str(s.get("orig", "")).lower() == "auto" else len(bytes.fromhex(str(s.get("orig", "")).replace(" ", "")))
            site = site_for(str(s["addr"]), f"{name}Source")
            if site is None:
                continue
            kept = str(s.get("shnext_orig", ""))
            if str(s.get("orig", "")).lower() != "auto":
                orig = bytes.fromhex(str(s["orig"]).replace(" ", ""))
            else:
                orig = original(site, str(s["addr"]), n, kept)
            if n < 5:
                errors.append(f"{where}: a hook needs at least 5 bytes")
                continue
            site["newValue"] = "jmp " + name + "\r\nnop" * (n - 5)
            site["defaultValue"] = (kept.replace("\n", "\r\n") + "\r\n") if kept else \
                ((ce.asm_text(orig, nop_ok=False) + "\r\n") if orig else "")
            # the cave: split at its block labels (one ShnExt code variable each, in this order);
            # blocks already written by another hook into the same cave are not repeated
            text = str(s.get("asm", "")).replace("\r", "")
            blocks: list[tuple[str, list[str]]] = []
            cur_label, cur = name, []
            for line in text.split("\n"):
                m = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*:\s*", line)
                if m and "__il_" not in m.group(1):
                    if m.group(1) == name and not cur and not blocks:
                        continue
                    blocks.append((cur_label, cur))
                    cur_label, cur = m.group(1), []
                else:
                    cur.append(line)
            blocks.append((cur_label, cur))
            # this tool's hooks jump back after the code by themselves; ShnExt caves say so
            # explicitly - add "jmp <return>" unless the code already ends in a jump / ret
            last = next((ln.split(";", 1)[0].strip() for ln in reversed(blocks[-1][1]) if ln.split(";", 1)[0].strip()), "")
            if not re.match(r"(jmp|ret|retn|ud2)\b", last, flags=re.IGNORECASE):
                ret = next((v["label"] for v in variables if v.get("type") == 6 and v.get("baseId") == site["label"]
                            and int(v.get("offset") or 0) == n), f"{name}Return")
                if ret not in by_label:
                    var(ret, type=6, defaultValue=0, baseId=site["label"], offset=n)
                blocks[-1][1].append(f"jmp ${ret}")
            for label, lines in blocks:
                if label in by_label:
                    if by_label[label].get("type") != 11 or by_label[label].get("baseId") not in ("", None):
                        errors.append(f"{where}: label '{label}' is also used for something else")
                    continue
                var(label, defaultValue=asm("\n".join(lines), where) + "\r\n")
            hooks += 1
        elif op in ("asmpatch", "write", "patch"):
            site = site_for(str(s["addr"]), f"site{i}")
            if site is None:
                continue
            if op == "asmpatch":
                import asmgen
                import codecave
                text = asm(s.get("asm", ""), where)
                try:
                    n = len(codecave.assemble_at(str(s.get("asm", "")), 0x400000, lambda e: 0x400000 + 0x1000))
                except Exception as exc:
                    errors.append(f"{where}: cannot assemble ({exc})")
                    continue
                site["newValue"] = text
            else:
                if str(s.get("type", "")).lower() not in ("hex", "bytes"):
                    errors.append(f"{where}: only byte (hex) writes can be written into a ShnExt")
                    continue
                b = bytes.fromhex(re.sub(r"\s+", "", str(s["value"])))
                n = len(b)
                if n > ce.SHNEXT_MAX_LINE and site.get("offsetFinder") is None and str(site["baseId"]).isdigit():
                    # onionHEN reads at most 1024 bytes per line: write consecutive pieces
                    kept = str(s.get("shnext_orig", ""))
                    o = None if kept else original(site, str(s["addr"]), n)
                    if o is None and not kept:
                        continue
                    variables.remove(site)
                    by_label.pop(site["label"], None)
                    for rel, on, off in ce._split_line(b, o or b"\0" * n):
                        var(f"{site['label']}_{rel:X}", baseId=site["baseId"], offset=int(site["offset"]) + rel,
                            isStatic=True, newValue=ce.asm_text(on),
                            defaultValue=(ce.asm_text(off, nop_ok=False) + "\r\n") if o else "")
                    continue
                site["newValue"] = ce.asm_text(b)
            kept = str(s.get("shnext_orig", ""))
            o = original(site, str(s["addr"]), n, kept)
            site["defaultValue"] = (kept.replace("\n", "\r\n") + "\r\n") if kept else \
                ((ce.asm_text(o, nop_ok=False) + "\r\n") if o else "")
        else:
            errors.append(f"{where}: '{op}' steps cannot be written into a ShnExt")
    renamed: dict = {}
    for s in steps:
        if isinstance(s.get("shnext_labels"), dict):
            renamed.update({str(k): str(v) for k, v in s["shnext_labels"].items()})
    renamed = {n: o for n, o in renamed.items() if o not in names}  # never clash with a name in use
    if renamed:
        pat = re.compile(r"(?<![\w.])(" + "|".join(map(re.escape, sorted(renamed, key=len, reverse=True))) + r")(?!\w)")
        for v in variables:
            for k in ("label", "baseId"):
                if v.get(k) in renamed:
                    v[k] = renamed[v[k]]
            for k in ("newValue", "defaultValue"):
                if isinstance(v.get(k), str) and v.get("type") == 11:
                    v[k] = pat.sub(lambda m: renamed[m.group(1)], v[k])
    for v in variables:
        if v["type"] == 11 and v.get("offsetFinder") is None and str(v["baseId"]).isdigit():
            v["isStatic"] = True
    patch = {"info": (cheat.description or "").replace("\n", "\r\n"), "name": cheat.name, "index": index,
             "author": getattr(cheat, "author", "") or author, "isMasterCode": bool(re.search(r"master\s*code", cheat.name, re.I)),
             "isIgnored": False, "Variables": variables}
    return (None if errors else patch), sorted(set(errors), key=errors.index)
