"""Read other PS4/PS5 cheat formats and turn them into this tool's cheats.

Supported
  .json      GoldHEN / ps4_cheats style   {"name","id","version","process","mods":[{"name","type","memory":[{offset,on,off}]}]}
  .shn       XML <Trainer><Cheat Text><Cheatline><Offset><Section><ValueOn><ValueOff>
  .mc4       encrypted .shn (base64 + AES-256-CBC, the public key used by every mc4 tool)
  ShnExt     a DECRYPTED ShnExt project: the *.ProjReap file (or its folder) + Patches/*.ReapPatch;
             patches that find their code with an AOB become `aob` + `hook` steps
  ps5pack / this tool's own JSON (handled by cheat_pack)

Offsets in .json/.shn/.mc4 are relative to the game executable (section 0) - written as
module(main)+0x...  (module(main#N)+0x... for section N).
"""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import aob as aobmod
import asmgen
from aes_cbc import cbc_decrypt

MC4_KEY = b"304c6528f659c766110239a51cl5dd9c"
MC4_IV = b"u@}kzW2u[u(8DWar"
TITLE_RE = re.compile(r"(?<![A-Za-z0-9])(PPSA\d{5}|CUSA\d{5})(?!\d)")   # "_" may touch it

EXTENSIONS = ("*.json", "*.shn", "*.mc4", "*.ps5c", "*.ProjReap", "*.ReapPatch")


class FormatError(Exception):
    pass


def _hex(text: str) -> str:
    h = re.sub(r"[^0-9A-Fa-f]", "", str(text).replace("0x", "").replace("0X", ""))
    if len(h) % 2:                     # like GoldHEN / onionHEN: "ABC" = 0A BC
        h = "0" + h
    return " ".join(h[i:i + 2] for i in range(0, len(h), 2)).upper()


def _off(text) -> int:
    t = str(text).strip()
    return int(t, 16) if not t.lower().startswith("0x") else int(t, 0)


def _base(section) -> str:
    try:
        n = int(str(section or "0").strip() or "0", 0)
    except ValueError:
        n = 0
    return "module(main)" if n == 0 else f"module(main#{n})"


def _is_true(v) -> bool:
    """<Absolute>true</Absolute> / "absolute": true"""
    return str(v).strip().lower() in ("1", "true", "yes", "y")


def _addr_expr(section, offset, absolute=False) -> str:
    """Absolute lines hold the real address; the rest are relative to the executable."""
    if absolute:
        return f"0x{_off(offset):X}"
    return f"{_base(section)}+0x{_off(offset):X}"


def _title(*texts: str) -> str:
    for t in texts:
        m = TITLE_RE.search(t or "")
        if m:
            return m.group(1)
    return ""


def _digits(text) -> int:
    return len(re.sub(r"[^0-9A-Fa-f]", "", str(text).replace("0x", "").replace("0X", "")))


def _line(section, offset, on: str, off: str, absolute=False) -> dict:
    """on / off: raw text from the file.  An off value with an odd number of hex digits is
    damaged (a digit is missing somewhere): it is not trusted - the bytes the game had before
    the cheat are restored instead."""
    on_hex = _hex(on)
    off_hex = "" if _digits(off) % 2 else (_hex(off) if str(off or "").strip() else "")
    try:
        sec = int(str(section or "0").strip() or "0", 0)
    except ValueError:
        sec = 0
    if not 0 <= sec < 64:                   # out of range: 0, like onionHEN
        sec = 0
    return {"sec": 0 if absolute else sec, "off": _off(offset), "abs": bool(absolute),
            "addr": _addr_expr(sec, offset, absolute), "on": on_hex, "offv": off_hex}


def _onoff_cheat(name: str, lines: list[dict], mode: str = "toggle", desc: str = "", mc=None) -> dict:
    """lines from _line().  Section N lines also carry the executable-base address ("alt") and
    their bytes ("verify"), so the runtime can use whichever is right (see cheats.Runtime._site);
    mc = the Master Code's first line, for a Master Code dependent."""
    steps, off = [], []
    for ln in lines:
        extra: dict = {}
        if mc is not None:
            extra = {"mc": {"addr": mc["addr"], "size": len(bytes.fromhex(mc["on"].replace(" ", ""))),
                            "offset": ln["off"]},
                     "verify": {"off": ln["offv"], "on": ln["on"]}}
        elif ln["sec"] and not ln["abs"]:
            extra = {"alt": f"module(main)+0x{ln['off']:X}", "verify": {"off": ln["offv"], "on": ln["on"]}}
        if mode == "once":                   # GoldHEN button: no undo, but keep its off bytes for re-export
            st = {"op": "write", "addr": ln["addr"], "type": "hex", "value": ln["on"], **extra}
            if ln["offv"].strip():
                st["button_off"] = ln["offv"]
            steps.append(st)
        elif ln["offv"].strip():
            steps.append({"op": "write", "addr": ln["addr"], "type": "hex", "value": ln["on"], **extra})
            off.append({"op": "write", "addr": ln["addr"], "type": "hex", "value": ln["offv"], **extra})
        else:
            steps.append({"op": "patch", "addr": ln["addr"], "type": "hex", "value": ln["on"], **extra})
    c = {"name": name, "mode": mode, "steps": steps}
    if desc:
        c["description"] = desc
    if mc is not None:
        c["description"] = ((desc + "\n") if desc else "") + "Needs the Master Code: turn that on first."
    if off and mode == "toggle":
        c["off"] = off
    return c


_MASTER_RE = re.compile(r"master\s*code", re.IGNORECASE)


def _cheats_with_master(raw: list[tuple[str, list[dict], str]]) -> list[dict]:
    """raw: (name, lines, mode).  GoldHEN / onionHEN Master Code rule: the first cheat named
    "Master Code" is the master; a cheat with "MC" in its name, one line, Section != 0 is a
    dependent whose real address is inside the code the master wrote."""
    master = next((lines[0] for name, lines, _m in raw if _MASTER_RE.search(name) and lines), None)
    out = []
    for name, lines, mode in raw:
        dep = (master is not None and "MC" in name and not _MASTER_RE.search(name)
               and len(lines) == 1 and lines[0]["sec"] != 0 and not lines[0]["abs"])
        out.append(_onoff_cheat(name, lines, mode, mc=master if dep else None))
    return out


# ------------------------------------------------------------------ GoldHEN json
def from_goldhen_json(d: dict) -> dict:
    raw = []
    for m in d.get("mods", []):
        lines = [_line(mem.get("section"), mem["offset"], mem.get("on", ""), mem.get("off") or "",
                       _is_true(mem.get("absolute", False)))
                 for mem in m.get("memory", [])
                 if str(mem.get("offset", "")).strip() and str(mem.get("on", "")).strip()]
        if not lines:                       # "TRAINER INFO (read only)" entries: text only, nothing to patch
            continue
        mode = "once" if str(m.get("type", "checkbox")).lower() == "button" else "toggle"
        raw.append((str(m.get("name", "cheat")), lines, mode))
    cheats = _cheats_with_master(raw)
    credits = d.get("credits") or []
    return {"format": "ps5cheat/1", "game": str(d.get("name") or d.get("id") or "game"),
            "title_id": str(d.get("id", "")).upper(), "version": str(d.get("version", "")),
            "process": str(d.get("process", "eboot.bin")), "author": ", ".join(map(str, credits)),
            "notes": "imported from GoldHEN json", "cheats": cheats}


# ------------------------------------------------------------------ SHN / MC4
def decrypt_mc4(data: bytes) -> str:
    try:
        raw = base64.b64decode(re.sub(rb"\s+", b"", data))
    except Exception as exc:
        raise FormatError(f"not an mc4 file (base64): {exc}") from None
    pt = cbc_decrypt(MC4_KEY, MC4_IV, raw)
    pad = pt[-1] if pt else 0
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    text = _decode_text(pt)
    if "<Trainer" not in text:           # some tools store the XML escaped a second time
        text = (text.replace("&lt;", "<").replace("&gt;", ">").replace("\\&quot;", '"').replace("\\&apos;", "'")
            .replace("&quot;", '"').replace("&apos;", "'"))
    m = re.search(r"<\?xml.*</Trainer>", text, flags=re.DOTALL) or re.search(r"<Trainer.*</Trainer>", text, re.DOTALL)
    if not m:
        raise FormatError("mc4 did not decrypt to a trainer (wrong file?)")
    return m.group(0)


def _decode_text(b: bytes) -> str:
    """UTF-8, or UTF-16 with a BOM (some .shn files are saved that way)."""
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", "replace")
    if len(b) > 3 and b[1:2] == b"\0" and b[3:4] == b"\0":
        return b.decode("utf-16-le", "replace")
    return b.decode("utf-8-sig", "replace")


_ATTR_RE = re.compile(r'(\s[\w:]+=")(.*?)("(?=\s+[\w:]+="|\s*/?>))', re.DOTALL)


def _repair_attrs(xml: str) -> str:
    """Escape stray quotes / & / < inside attribute values: Text="Max YEN "After Used" " """
    def tag(m: re.Match) -> str:
        return _ATTR_RE.sub(lambda a: a.group(1) + a.group(2).replace("&", "&amp;").replace("&amp;amp;", "&amp;")
                            .replace('"', "&quot;").replace("<", "&lt;") + a.group(3), m.group(0))
    return re.sub(r"<[A-Za-z][^<>]*?/?>", tag, xml)


def from_shn(text: str, source: str = "shn") -> dict:
    m = re.search(r"<Trainer\b.*</Trainer>", text, flags=re.DOTALL)   # drop padding / junk around it
    text = (m.group(0) if m else text).strip().lstrip("\ufeff")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        try:                                # files hand-edited or written by lenient tools
            root = ET.fromstring(_repair_attrs(text))
        except ET.ParseError:
            raise FormatError(f"bad SHN xml: {exc}") from None
    if root.tag != "Trainer":
        raise FormatError("not an SHN trainer (no <Trainer>)")
    raw = []
    for ch in root.findall("Cheat"):
        lines = [_line(cl.findtext("Section"), (cl.findtext("Offset") or "0").strip(),
                       cl.findtext("ValueOn") or "", cl.findtext("ValueOff") or "",
                       _is_true(cl.findtext("Absolute") or ""))
                 for cl in ch.findall("Cheatline")
                 if (cl.findtext("Offset") or "").strip() and (cl.findtext("ValueOn") or "").strip()]
        if lines:
            raw.append((ch.get("Text") or "cheat", lines, "toggle"))
    cheats = _cheats_with_master(raw)
    tid = (root.get("Cusa") or "").strip().upper()
    return {"format": "ps5cheat/1", "game": root.get("Game") or tid or "game", "title_id": tid,
            "version": root.get("Version") or "", "process": root.get("Process") or "eboot.bin",
            "author": root.get("Moder") or "", "notes": f"imported from {source}", "cheats": cheats}


# ------------------------------------------------------------------ decrypted ShnExt
_IDENT = r"[A-Za-z_]\w*"


def _reap_cheat(p: dict, notes: list[str]) -> dict:
    """One .ReapPatch -> one toggle cheat."""
    vars_ = {v["label"]: v for v in p.get("Variables", []) if v.get("label")}
    finders = {k: v for k, v in vars_.items() if v.get("type") == 11 and v.get("offsetFinder")}
    addrs = {k: v for k, v in vars_.items() if v.get("type") == 6}
    # code at a fixed offset from the executable (no AOB): baseId "0" + offset, e.g.
    # {"label":"healthSource","baseId":"0","offset":31563972,"newValue":"nop:6","defaultValue":"mov ..."}
    # (code-cave blocks have baseId "" and isStatic false; fixed patches are marked isStatic)
    statics = {k: v for k, v in vars_.items() if v.get("type") == 11 and not v.get("offsetFinder")
               and (v.get("isStatic") is True or (str(v.get("baseId") or "") == "0" and int(v.get("offset") or 0) > 0))
               and str(v.get("baseId") or "0") == "0" and str(v.get("newValue") or "").strip()}
    codes = {k: v for k, v in vars_.items() if v.get("type") == 11 and not v.get("offsetFinder")
             and not v.get("baseId") and k not in statics}
    sites = {k: v for k, v in vars_.items() if v.get("type") == 11 and not v.get("offsetFinder")
             and v.get("baseId") and v.get("baseId") != "0"}
    data = {k: v for k, v in vars_.items() if k not in finders and k not in addrs and k not in codes
            and k not in sites and k not in statics}
    name = str(p.get("name") or "patch")
    steps: list[dict] = []
    params: list[dict] = []
    first_site: Optional[str] = None

    # 1. locate the code with the AOB signatures
    for lbl, v in finders.items():
        f = v["offsetFinder"]
        pat, mask = aobmod.from_b64(f.get("UniqueAOB", ""), f.get("Mask"))
        st = {"op": "aob", "pattern": aobmod.fmt(pat, mask), "store": lbl}
        sec = int(f.get("sectionId") or 0)
        if sec:
            st["module"] = f"main#{sec}"
            st["data"] = True
        if v.get("offset"):
            st["offset"] = int(v["offset"])
        if f.get("ptr"):
            notes.append(f"{name}: '{lbl}' uses a pointer offset finder (ptr={f['ptr']}) - not supported, "
                         "check the address")
        steps.append(st)
        first_site = first_site or lbl
    # 2. computed addresses (label = other label + offset)
    for lbl, v in addrs.items():
        base, off = str(v.get("baseId") or ""), int(v.get("offset") or 0)
        expr = f"${base}" if base in vars_ else "module(main)"
        steps.append({"op": "set", "var": lbl, "value": f"{expr}+0x{off:X}" if off else expr})
    # 3. data variables -> small buffers next to the code (RIP-relative reach), user inputs
    for lbl, v in data.items():
        dv = v.get("defaultValue", 0)
        is_float = isinstance(dv, float) and not float(dv).is_integer()
        typ = "f32" if is_float else "u64"
        st: dict = {"op": "alloc", "name": lbl, "size": 16, "prot": "rw"}
        if first_site:
            st["near"] = f"${first_site}"
        if v.get("editor") is not None:
            params.append({"name": lbl, "label": v.get("DisplayName") or lbl, "type": typ, "default": str(dv)})
            st["init"] = {"type": typ, "value": f"${lbl}"}
        else:
            st["init"] = {"type": typ, "value": dv if is_float else str(int(dv or 0))}
        steps.append(st)

    def translate(asm: str) -> str:
        out = []
        for line in str(asm).replace("\r", "").split("\n"):
            def mem(m: re.Match) -> str:
                lbl, rest = m.group(1), m.group(2) or ""
                ref = f"@{lbl}" if lbl in data or lbl in codes else f"${lbl}"
                return f"[rip:{ref}{rest.replace(' ', '')}]"
            line = re.sub(rf"\[\s*({_IDENT})\s*([+-]\s*(?:0x[0-9A-Fa-f]+|\d+))?\s*\]",
                          lambda m: mem(m) if m.group(1) in vars_ else m.group(0), line)

            def bare(m: re.Match) -> str:
                lbl = m.group(0)
                if lbl not in vars_:
                    return lbl
                return f"@{lbl}" if lbl in data or lbl in codes else f"${lbl}"
            # only outside [rip:...] markers
            parts = re.split(r"(\[rip:[^\]]*\])", line)
            line = "".join(pt if pt.startswith("[rip:") else re.sub(rf"(?<![@$\w]){_IDENT}", bare, pt)
                           for pt in parts)
            out.append(line)
        return "\n".join(out).strip()

    # 4. each AOB site whose new code is "jmp <cave>" (+nops) becomes a hook
    hooked: set[str] = set()
    patch_steps: list[dict] = []
    for lbl, v in list(finders.items()) + list(sites.items()) + list(statics.items()):
        new = str(v.get("newValue") or "").replace("\r", "").strip()
        if not new:
            continue
        if lbl in statics:
            site = f"module(main)+0x{int(v['offset']):X}"
        elif lbl in finders:
            site = f"${lbl}"
        else:
            site = f"${v['baseId']}+0x{int(v.get('offset') or 0):X}"
        nop = re.fullmatch(r"nop\s*:\s*(\d+)", new, flags=re.IGNORECASE)
        if nop:                         # ShnExt shorthand: N bytes of 0x90 (original restored on off)
            n = int(nop.group(1))
            if not 0 < n <= 4096:
                notes.append(f"{name}: '{lbl}' has a bad nop count ({new})")
                continue
            patch_steps.append({"op": "patch", "addr": site, "type": "hex", "value": " ".join(["90"] * n)})
            continue
        m = re.fullmatch(rf"jmp\s+({_IDENT})((?:\s*\n\s*nop)*)\s*", new, flags=re.IGNORECASE)
        try:
            new_len = len(asmgen.assemble(re.sub(rf"\b{m.group(1)}\b", "0x40000000", new) if m else "nop"))
        except Exception:
            new_len = 0
        if m and m.group(1) in codes and new_len >= 5:
            target = m.group(1)
            orig_hex = ""
            if lbl in finders:
                pat, mask = aobmod.from_b64(finders[lbl]["offsetFinder"].get("UniqueAOB", ""),
                                            finders[lbl]["offsetFinder"].get("Mask"))
                off = int(v.get("offset") or 0)
                if len(pat) >= off + new_len and all(mask[off:off + new_len]):
                    orig_hex = pat[off:off + new_len].hex(" ").upper()
            if not orig_hex:
                try:
                    b = asmgen.assemble(str(v.get("defaultValue") or "").replace("\r", ""))
                    if len(b) == new_len:
                        orig_hex = b.hex(" ").upper()
                except Exception:
                    pass
            cave = translate(codes[target].get("defaultValue") or "")
            # the hook appends the jump back to (site + replaced bytes) itself
            ret = next((r for r, rv in addrs.items() if rv.get("baseId") == lbl
                        and int(rv.get("offset") or 0) == new_len), None)
            if ret:
                cave = re.sub(rf"\n?\s*jmp\s+\${ret}\s*$", "", cave, flags=re.IGNORECASE)
            st = {"op": "hook", "name": target, "addr": site, "asm": cave}
            if orig_hex:
                st["orig"] = orig_hex
            else:
                st["orig"], st["length"] = "auto", new_len
            patch_steps.append(st)
            hooked.add(target)
        else:
            patch_steps.append({"op": "asmpatch", "addr": site, "asm": translate(new)})
    # 5. code blocks not reached through a hook: plain code buffers near the game code
    for lbl, v in codes.items():
        if lbl in hooked:
            continue
        st = {"op": "code", "name": lbl, "asm": translate(v.get("defaultValue") or ""), "auto_frame": False,
              "auto_ret": False, "prot": "rx"}
        if first_site:
            st["near"] = f"${first_site}"
        steps.append(st)
    steps += patch_steps

    cheat = {"name": name, "mode": "toggle", "steps": steps}
    if params:
        cheat["params"] = params
    if p.get("info"):
        cheat["description"] = str(p["info"]).replace("\r", "")
    if p.get("author"):
        cheat["author"] = str(p["author"])
    if p.get("isMasterCode") and not re.search(r"master\s*code", name, re.IGNORECASE):
        cheat["name"] = f"{name} (master code)"
    return cheat


def from_shnext_folder(proj: Path) -> tuple[dict, list[str]]:
    """proj: the *.ProjReap file, its folder, or one *.ReapPatch file."""
    notes: list[str] = []
    if proj.is_dir():
        folder = proj
        meta_files = sorted(folder.glob("*.ProjReap"))
        patches = sorted((folder / "Patches").glob("*.ReapPatch")) or sorted(folder.glob("*.ReapPatch"))
    elif proj.suffix.lower() == ".projreap":
        folder, meta_files = proj.parent, [proj]
        patches = sorted((folder / "Patches").glob("*.ReapPatch"))
    else:                                          # a single .ReapPatch
        folder = proj.parent.parent if proj.parent.name.lower() == "patches" else proj.parent
        meta_files = sorted(folder.glob("*.ProjReap"))
        patches = [proj]
    meta = {}
    if meta_files:
        meta = json.loads(meta_files[0].read_text(encoding="utf-8-sig"))
    if not patches:
        raise FormatError("no Patches/*.ReapPatch files found - pick the decrypted ShnExt project")
    loaded = []
    for pf in patches:
        try:
            loaded.append(json.loads(pf.read_text(encoding="utf-8-sig")))
        except Exception as exc:
            notes.append(f"{pf.name}: {exc}")
    src_name = meta_files[0].name if meta_files else patches[0].name
    game, more = from_shnext_data(meta, loaded, src_name)
    return game, notes + more


def from_shnext_data(meta: dict, loaded: list[dict], src_name: str) -> tuple[dict, list[str]]:
    """Decrypted ShnExt in memory: project metadata + the ReapPatch dicts (no files needed)."""
    notes: list[str] = []
    loaded = sorted(loaded, key=lambda d: d.get("index", 0))
    cheats = []
    for p in loaded:
        if p.get("isIgnored"):
            notes.append(f"{p.get('name')}: marked ignored in the project, imported anyway")
        cheats.append(_reap_cheat(p, notes))
    tid = _title(src_name, str(meta.get("Game", "")), str(meta.get("Cusa", "")))
    gname = src_name.split(tid)[0].strip("-_ ").replace("-", " ") if tid and tid in src_name else ""
    authors = sorted({c.get("author", "") for c in cheats if c.get("author")})
    # "Game" is the real title in some projects ("Assassin's Creed Mirage") and an id in others
    # ("PSA25286_00-0206770389642527") - use it only when it reads like a name
    stored = str(meta.get("Game") or "").strip()
    if not re.search(r"[A-Za-z]{2}", stored) or re.match(r"[A-Z]{3,4}\d{3,}", stored) or " " not in stored and "_" in stored:
        stored = ""
    game = {"format": "ps5cheat/1", "game": stored or gname or tid or "game", "title_id": tid,
            "version": str(meta.get("Version", "")), "process": str(meta.get("ProcessName") or "eboot.bin"),
            "author": ", ".join(authors), "notes": str(meta.get("Comment", "")).replace("\r", ""),
            "cheats": cheats}
    return game, notes


# ------------------------------------------------------------------ entry point
def load_any(path: Path) -> tuple[dict, list[str]]:
    """-> (ps5pack dict, notes).  Accepts every format listed at the top."""
    import cheat_pack
    path = Path(path)
    suf = path.suffix.lower()
    if path.is_dir() or suf in (".projreap", ".reappatch"):
        game, notes = from_shnext_folder(path)
        return {"format": "ps5pack/1", "games": [game], "items": {}}, notes
    data = path.read_bytes()
    if suf == ".mc4":
        return {"format": "ps5pack/1", "games": [from_shn(decrypt_mc4(data), "mc4")], "items": {}}, []
    if suf == ".shn" or data.lstrip(b"\xef\xbb\xbf \r\n\t").startswith((b"<?xml", b"<Trainer")) \
            or data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return {"format": "ps5pack/1", "games": [from_shn(_decode_text(data))], "items": {}}, []
    if suf == ".ps5c":
        return cheat_pack.parse(data), []
    if suf == ".shnext" or (data[:1] not in (b"{", b"[") and not data.lstrip()[:1] in (b"{", b"[")):
        import zlib
        try:
            inner = zlib.decompress(data, -15)
        except zlib.error:
            inner = b""
        if b'"patchEntries"' in inner:
            raise FormatError("this is an encrypted ShnExt - open it in the Cheat Player (it decrypts in "
                              "memory), or import a decrypted ShnExt project (*.ProjReap or its folder)")
    try:
        d = json.loads(data.decode("utf-8-sig"))
    except Exception:
        # an mc4 without its extension?
        try:
            return {"format": "ps5pack/1", "games": [from_shn(decrypt_mc4(data), "mc4")], "items": {}}, []
        except Exception:
            raise FormatError("unknown cheat file format") from None
    if isinstance(d, dict) and "mods" in d:
        return {"format": "ps5pack/1", "games": [from_goldhen_json(d)], "items": {}}, []
    if isinstance(d, dict) and "patchEntries" in d:
        raise FormatError("this is an encrypted ShnExt (.ShnExt.json) - decrypt it first, then import the "
                          "decrypted project (*.ProjReap or its folder)")
    if isinstance(d, dict) and "Variables" in d:
        game, notes = from_shnext_folder(path)
        return {"format": "ps5pack/1", "games": [game], "items": {}}, notes
    return cheat_pack.parse(data), []
