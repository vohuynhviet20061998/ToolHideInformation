#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PII Shield - che thong tin ca nhan trong file .doc/.docx/.pdf (va .txt...)
roi KHOI PHUC lai nhu cu tu mot "ket" (vault) luu tren may.

  Che   : 0912 345 678  ->  [[PHONE_001]]      (ghi cap "token <-> gia tri that" vao vault)
  Khoi phuc: file bat ky chua [[PHONE_001]] -> 0912 345 678

Chay khong tham so  -> mo giao dien.
Chay co tham so     -> dong lenh (xem --help).
"""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from collections import Counter
from urllib.parse import quote, unquote

from lxml import etree

try:
    import pymupdf
except ImportError:  # ban PyMuPDF cu
    try:
        import fitz as pymupdf
    except ImportError:
        pymupdf = None

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VAULT = os.path.join(APP_DIR, "pii_vault.json")

# loai thong tin -> nhan hien thi
TYPE_LABELS = {
    "EMAIL": "Email",
    "PHONE": "Số điện thoại",
    "ID": "CCCD / CMND / Hộ chiếu",
    "TAX": "Mã số thuế",
    "BANK": "Số tài khoản ngân hàng",
    "DOB": "Ngày sinh",
    "NAME": "Họ tên (sau Ông/Bà/Đại diện...)",
    "ADDR": "Địa chỉ",
}
DEFAULT_TYPES = list(TYPE_LABELS)

# [[PHONE_001]] - chap nhan ca dang bi AI/markdown them dau \ hoac khoang trang
TOKEN_RE = re.compile(r"\\?\[\\?\[\s*([A-Z]+)\\?_(\d{3,})\s*\\?\]\\?\]")


class PIIError(Exception):
    pass


# --------------------------------------------------------------------------
# VAULT: noi luu cap token <-> gia tri that
# --------------------------------------------------------------------------
class Vault:
    def __init__(self, path=DEFAULT_VAULT, password=None):
        self.path = path
        self.password = password or None
        self.counters: dict[str, int] = {}
        self.items: dict[str, dict] = {}      # token -> {"type","value"}
        self.rev: dict[tuple, str] = {}       # (type, value) -> token
        self._salt = None
        self._load()

    # -- ma hoa (tuy chon) --
    def _fernet(self, salt):
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=300_000)
        return Fernet(base64.urlsafe_b64encode(kdf.derive(self.password.encode("utf-8"))))

    def _load(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if raw.get("enc"):
            if not self.password:
                raise PIIError("Vault đang được mã hóa bằng mật khẩu - hãy nhập mật khẩu.")
            self._salt = base64.b64decode(raw["salt"])
            try:
                data = json.loads(self._fernet(self._salt).decrypt(raw["data"].encode()))
            except Exception:
                raise PIIError("Sai mật khẩu vault.")
        else:
            data = raw
        self.counters = data.get("counters", {})
        self.items = data.get("items", {})
        self.rev = {self._key(v["type"], v["value"]): t for t, v in self.items.items()}

    def save(self):
        data = {"v": 1, "counters": self.counters, "items": self.items}
        if self.password:
            self._salt = self._salt or os.urandom(16)
            out = {"v": 1, "enc": True, "salt": base64.b64encode(self._salt).decode(),
                   "data": self._fernet(self._salt).encrypt(json.dumps(data, ensure_ascii=False).encode()).decode()}
        else:
            out = data
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    @staticmethod
    def _key(typ, value):
        return (typ, " ".join(value.split()))   # NBSP/khoang trang kep coi nhu nhau

    def token_for(self, typ, value):
        value = value.replace(" ", " ")
        key = self._key(typ, value)
        if key in self.rev:
            return self.rev[key]
        n = self.counters.get(typ, 0) + 1
        self.counters[typ] = n
        tok = f"[[{typ}_{n:03d}]]"
        self.items[tok] = {"type": typ, "value": value}
        self.rev[key] = tok
        return tok

    def lookup(self, token):
        it = self.items.get(token)
        return it["value"] if it else None


# --------------------------------------------------------------------------
# NHAN DIEN THONG TIN CA NHAN
# --------------------------------------------------------------------------
_WORD = re.compile(r"[^\W\d_]+(?:['’\-][^\W\d_]+)*")
_NAME_STOP = {"công", "cty", "ngân", "bên", "phòng", "chi", "trung", "tổng", "hội", "ban", "sở",
              "ubnd", "tnhh", "cp", "công ty", "doanh", "nghiệp", "hợp", "tác", "xã", "thang", "máy"}
_NAME_LABEL = re.compile(
    r"(?i:(?<!\w)(?:(?:người\s+)?đại\s+diện(?:\s+bên\s+[ab])?|ông|bà|anh|chị|mr\.?|mrs\.?|ms\.?|miss|"
    r"họ\s*(?:và\s*)?tên|full\s*name|người\s+liên\s+hệ|kính\s+gửi|giám\s+đốc)(?!\w)\s*[:：\-]?\s*)+")
_ADDR = re.compile(
    r"(?im)(?:địa\s*chỉ(?:\s*(?:thường\s*trú|liên\s*hệ|trụ\s*sở|giao\s*hàng|nhận\s*hàng))?|trụ\s*sở(?:\s*chính)?|"
    r"thường\s*trú|address)\s*[:：]\s*"
    r"([^\n\r\t;|]{6,}?)(?=\s*(?:[;|\t\r\n]|(?i:điện\s*thoại|đt|sđt|tel|fax|mst|email|website)\b|\Z|$))")
_ID_LABEL = re.compile(
    r"(?i:cmnd|cccd|cmt|căn\s*cước(?:\s*công\s*dân)?|hộ\s*chiếu|passport|số\s*định\s*danh(?:\s*cá\s*nhân)?)"
    r"[^\d\n]{0,25}?\b([A-Z]{0,2}\d{7,12})(?!\d)")
_TAX = re.compile(
    r"(?i:mst|mã\s*số\s*thuế|tax\s*(?:code|id|no\.?))[^\d\n]{0,15}?(\d{10}(?:-\d{3})?|\d{13})(?!\d)")
_BANK = re.compile(
    r"(?i:stk|số\s*tk|số\s*tài\s*khoản|tài\s*khoản(?:\s*số)?|account\s*(?:no\.?|number)?)[^\d\n]{0,15}?(\d[\d .\-]{6,20}\d)")
_DOB = re.compile(
    r"(?i:sinh\s*ngày|ngày\s*sinh|date\s*of\s*birth|dob)[^\d\n]{0,10}?"
    r"(\d{1,2}\s*(?:/|-|\.|tháng)\s*\d{1,2}\s*(?:/|-|\.|năm)\s*\d{2,4})")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<![\d+])(?:\+84(?:[ .\-]?\d){9}|0(?:[ .\-]?\d){9,10})(?!\d)")
_ID12 = re.compile(r"(?<!\d)\d{12}(?!\d)")


def _trim(text, s, e):
    while e > s and text[e - 1] in " .,;:-\u00a0":
        e -= 1
    while s < e and text[s] in " \u00a0":
        s += 1
    return (s, e) if e > s else None


def _grp(m, text):
    return _trim(text, m.start(1), m.end(1))


def _name_span(m, text):
    pos, end, words, i = m.end(), m.end(), 0, m.end()
    while words < 5:
        w = _WORD.match(text, i)
        if not w or not w.group()[0].isupper() or w.group().lower() in _NAME_STOP:
            break
        words += 1
        end = w.end()
        if text[end:end + 1] in (" ", "\u00a0"):
            i = end + 1
        else:
            break
    return (pos, end) if words >= 2 else None


def _phone_span(m, text):
    d = re.sub(r"\D", "", m.group())
    ok = (d.startswith("84") and len(d) == 11) or (d.startswith("0") and len(d) in (10, 11))
    return (m.start(), m.end()) if ok else None


def _bank_span(m, text):
    n = len(re.sub(r"\D", "", m.group(1)))
    return _grp(m, text) if 8 <= n <= 19 else None


_FAM: dict = {}
for _cp in range(0xC0, 0x1EFA):
    _c = chr(_cp)
    _b = unicodedata.normalize("NFD", _c)[0].lower() if _c not in "đĐ" else "d"
    if _b.isascii() and _b.isalpha() and _c.lower() != _b and unicodedata.category(_c).startswith("L"):
        _FAM.setdefault(_b, set()).add(_c.lower())


def _fuzzy(rx):
    """Chu co dau trong mau regex -> chap nhan ca dang mat dau (vd. 'địa chỉ' khop 'Dia chi')."""
    out = []
    for ch in rx.pattern:
        b = ("d" if ch in "đĐ" else unicodedata.normalize("NFD", ch)[0].lower()) if not ch.isascii() else None
        if b and b in _FAM and unicodedata.category(ch).startswith("L"):
            out.append("[" + b + "".join(sorted(_FAM[b])) + "]")
        else:
            out.append(ch)
    return re.compile("".join(out), rx.flags)


_NAME_LABEL, _ADDR, _ID_LABEL, _TAX, _BANK, _DOB = (
    _fuzzy(r) for r in (_NAME_LABEL, _ADDR, _ID_LABEL, _TAX, _BANK, _DOB))

# (uu tien, loai, regex, ham lay (start,end))   uu tien nho = thang khi chong lan
_RULES = [
    (1, "ID", _ID_LABEL, _grp),
    (1, "TAX", _TAX, _grp),
    (1, "BANK", _BANK, _bank_span),
    (1, "DOB", _DOB, _grp),
    (1, "ADDR", _ADDR, _grp),
    (1, "NAME", _NAME_LABEL, _name_span),
    (1, "EMAIL", _EMAIL, lambda m, t: (m.start(), m.end())),
    (2, "PHONE", _PHONE, _phone_span),
    (3, "ID", _ID12, lambda m, t: (m.start(), m.end())),
]


class Engine:
    """Nhan dien + thay the, dung chung cho docx / pdf / txt."""

    def __init__(self, vault, enabled=None, terms=()):
        self.vault = vault
        self.enabled = set(DEFAULT_TYPES if enabled is None else enabled)
        self.term_rx = []
        for t in terms:
            t = t.strip()
            if len(t) >= 3:
                self.term_rx.append(re.compile(
                    r"(?<!\w)" + r"\s+".join(map(re.escape, t.split())) + r"(?!\w)", re.I))
        self.stats: Counter = Counter()     # so lan da che / khoi phuc theo loai
        self.missing: Counter = Counter()   # token khong co trong vault

    def detect(self, text):
        text = text.replace(" ", " ")      # PDF hay dung NBSP; thay 1-1 nen vi tri khong doi
        cands = []
        for rx in self.term_rx:
            for m in rx.finditer(text):
                cands.append((0, m.start(), m.end(), "CUSTOM"))
        for prio, typ, rx, fn in _RULES:
            if typ not in self.enabled:
                continue
            for m in rx.finditer(text):
                sp = fn(m, text)
                if sp:
                    cands.append((prio, sp[0], sp[1], typ))
        cands.sort(key=lambda c: (c[0], -(c[2] - c[1]), c[1]))
        chosen = []
        for c in cands:
            if all(c[2] <= x[1] or c[1] >= x[2] for x in chosen):
                chosen.append(c)
        chosen.sort(key=lambda c: c[1])
        return [(c[1], c[2], c[3]) for c in chosen]

    def mask_spans(self, text):
        out = []
        for s, e, typ in self.detect(text):
            out.append((s, e, self.vault.token_for(typ, text[s:e])))
            self.stats[typ] += 1
        return out

    def restore_spans(self, text):
        out = []
        for m in TOKEN_RE.finditer(text):
            tok = f"[[{m.group(1)}_{m.group(2)}]]"
            val = self.vault.lookup(tok)
            if val is None:
                self.missing[tok] += 1
                continue
            out.append((m.start(), m.end(), val))
            self.stats[m.group(1)] += 1
        return out


def apply_spans(text, spans):
    out, last = [], 0
    for s, e, rep in spans:
        out.append(text[last:s])
        out.append(rep)
        last = e
    out.append(text[last:])
    return "".join(out)


# --------------------------------------------------------------------------
# DOCX  (sua truc tiep XML trong file zip -> giu nguyen dinh dang)
# --------------------------------------------------------------------------
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_P, _T = f"{{{W}}}p", f"{{{W}}}t"
_XMLSPACE = "{http://www.w3.org/XML/1998/namespace}space"
_PART_RE = re.compile(r"^word/(document|header\d*|footer\d*|footnotes|endnotes|comments\w*)\.xml$")


def _collect_ts(p):
    ts = []

    def walk(el):
        for c in el:
            if c.tag == _P:       # doan long (o van ban) se duoc xu ly rieng
                continue
            if c.tag == _T:
                ts.append(c)
            walk(c)
    walk(p)
    return ts


def _rewrite(ts, spans):
    """Thay cac khoang [s,e) cua chuoi noi tu cac <w:t>, giu dinh dang run dau tien."""
    for s, e, rep in reversed(spans):
        pos, first = 0, True
        for t in ts:
            txt = t.text or ""
            a, b = pos, pos + len(txt)
            pos = b
            if b <= s or a >= e:
                continue
            ls, le = max(s, a) - a, min(e, b) - a
            t.text = txt[:ls] + (rep if first else "") + txt[le:]
            t.set(_XMLSPACE, "preserve")
            first = False


def _docx_part(data, engine, mode):
    root = etree.fromstring(data, etree.XMLParser(resolve_entities=False, huge_tree=True))
    for p in root.iter(_P):
        ts = _collect_ts(p)
        if not ts:
            continue
        full = "".join(t.text or "" for t in ts)
        if mode == "restore" and "[" not in full:
            continue
        if not full.strip():
            continue
        spans = engine.mask_spans(full) if mode == "mask" else engine.restore_spans(full)
        if spans:
            _rewrite(ts, spans)
    if mode == "mask":
        for el in root.iter():
            for att in ("author", "initials"):
                if f"{{{W}}}{att}" in el.attrib:
                    el.set(f"{{{W}}}{att}", "Author")
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def _docx_rels(data, engine, mode):
    """mailto:/tel: nam trong file .rels cung phai che."""
    text = data.decode("utf-8")
    if mode == "mask":
        def sub(m):
            raw = unquote(m.group(2))
            spans = engine.mask_spans(raw)
            return m.group(1) + quote(apply_spans(raw, spans), safe="") if spans else m.group(0)
        text = re.sub(r"(mailto:|tel:)([^\"?#]+)", sub, text)
    else:
        text = text.replace("%5B%5B", "[[").replace("%5D%5D", "]]")
        text = apply_spans(text, engine.restore_spans(text))
    return text.encode("utf-8")


def _scrub_props(data):
    root = etree.fromstring(data)
    for el in root.iter():
        if isinstance(el.tag, str) and etree.QName(el).localname in ("creator", "lastModifiedBy", "Company", "Manager"):
            el.text = ""
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def process_docx(src, dst, engine, mode):
    try:
        zin = zipfile.ZipFile(src)
    except zipfile.BadZipFile:
        raise PIIError("File Word không đọc được (có thể đang đặt mật khẩu / hỏng).")
    with zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if _PART_RE.match(item.filename):
                data = _docx_part(data, engine, mode)
            elif item.filename.endswith(".rels"):
                data = _docx_rels(data, engine, mode)
            elif mode == "mask" and item.filename in ("docProps/core.xml", "docProps/app.xml"):
                data = _scrub_props(data)
            zout.writestr(item, data)
    return []


def doc_to_docx(src):
    """Doi file Office cu (.doc -> .docx, .xls -> .xlsx) bang Word/Excel (COM) hoac LibreOffice."""
    ext = os.path.splitext(src)[1].lower()
    app, new_ext = {".doc": ("Word.Application", ".docx"), ".xls": ("Excel.Application", ".xlsx")}[ext]
    tmp = tempfile.mkdtemp(prefix="pii_")
    out = os.path.join(tmp, os.path.splitext(os.path.basename(src))[0] + new_ext)
    last = None
    try:
        import win32com.client
        office = win32com.client.DispatchEx(app)
        office.Visible = False
        office.DisplayAlerts = False if ext == ".xls" else 0
        try:
            if ext == ".doc":
                d = office.Documents.Open(os.path.abspath(src), ReadOnly=True, AddToRecentFiles=False,
                                          ConfirmConversions=False)
                d.SaveAs2(out, FileFormat=16)
            else:
                d = office.Workbooks.Open(os.path.abspath(src), ReadOnly=True, UpdateLinks=0)
                d.SaveAs(out, FileFormat=51)
            d.Close(False)
        finally:
            try:
                office.Quit()
            except Exception:
                pass
        return out
    except ImportError:
        pass
    except Exception as e:  # Office loi -> thu LibreOffice
        last = e
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if soffice:
        subprocess.run([soffice, "--headless", "--convert-to", new_ext[1:], "--outdir", tmp, src],
                       check=True, capture_output=True)
        if os.path.exists(out):
            return out
    raise PIIError(f"Không đổi được {ext} sang {new_ext} (cần cài Microsoft Office + pywin32, hoặc LibreOffice)."
                   + (f" Lỗi: {last}" if last else ""))


# --------------------------------------------------------------------------
# PDF  (PyMuPDF: xoa that su chu goc roi ve token / chu goc len cho cu)
# --------------------------------------------------------------------------
def _unicode_font():
    for p in (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\tahoma.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/Library/Fonts/Arial.ttf",
              "/System/Library/Fonts/Supplemental/Arial.ttf"):
        if os.path.exists(p):
            return p
    return None


_OCR = None


def ocr_lang():
    """Ngon ngu OCR kha dung ('vie+eng' / 'eng') hoac None neu chua co thu muc tessdata.
    PyMuPDF da kem san Tesseract, chi can file *.traineddata trong thu muc tessdata canh tool."""
    global _OCR
    if _OCR is None:
        folders = [os.environ.get("TESSDATA_PREFIX", ""), os.path.join(APP_DIR, "tessdata"),
                   r"C:\Program Files\Tesseract-OCR	essdata"]
        _OCR = False
        for d in folders:
            if d and os.path.exists(os.path.join(d, "eng.traineddata")):
                os.environ["TESSDATA_PREFIX"] = d
                _OCR = "vie+eng" if os.path.exists(os.path.join(d, "vie.traineddata")) else "eng"
                break
    return _OCR or None


def _page_spans(page, tp=None):
    return [s for b in page.get_text("dict", textpage=tp)["blocks"] for l in b.get("lines", []) for s in l["spans"]]


def _metrics(r, spans):
    """Tu o chu tim duoc (r) suy ra o chu CHAT + duong co so + co chu + mau cua dong chu do.
    Font nhu Cambria co khung chu cao gap 5 lan co chu, nen khong the dung r de xoa (se an sang dong ben canh)."""
    best, area = None, 0.0
    for s in spans:
        a = (pymupdf.Rect(s["bbox"]) & r).get_area()
        if a > area:
            best, area = s, a
    if best is None:
        base, z, col = r.y1 - r.height * 0.22, max(r.height * 0.78, 5.0), (0, 0, 0)
    else:
        base, z, c = best["origin"][1], best["size"], best["color"]
        col = (((c >> 16) & 255) / 255, ((c >> 8) & 255) / 255, (c & 255) / 255)
    return pymupdf.Rect(r.x0, base - 0.8 * z, r.x1, base + 0.22 * z), base, z, col


def _apply_redactions(page, pixels=False):
    kw = {}
    if hasattr(pymupdf, "PDF_REDACT_IMAGE_NONE"):
        kw["images"] = pymupdf.PDF_REDACT_IMAGE_PIXELS if pixels else pymupdf.PDF_REDACT_IMAGE_NONE
    if hasattr(pymupdf, "PDF_REDACT_LINE_ART_NONE"):
        kw["graphics"] = pymupdf.PDF_REDACT_LINE_ART_NONE
    try:
        page.apply_redactions(**kw)
    except TypeError:
        page.apply_redactions()


def _find_rects(page, s, tp=None):
    rects = page.search_for(s, textpage=tp) or page.search_for(" ".join(s.split()), textpage=tp)
    # mot cum tu co the tra ve nhieu o roi nhau tren cung dong -> gop lai thanh 1
    merged = []
    for r in sorted(rects, key=lambda r: (round(r.y0), r.x0)):
        for i, m in enumerate(merged):
            if abs(m.y0 - r.y0) < 3 and r.x0 - m.x1 < 12 and r.x0 >= m.x0:
                merged[i] = pymupdf.Rect(min(m.x0, r.x0), min(m.y0, r.y0), max(m.x1, r.x1), max(m.y1, r.y1))
                break
        else:
            merged.append(pymupdf.Rect(r))
    return merged


def _chars(t):
    return Counter(c for c in t if not c.isspace())


def process_pdf(src, dst, engine, mode):
    if pymupdf is None:
        raise PIIError("Thiếu thư viện PyMuPDF (pip install pymupdf).")
    doc = pymupdf.open(src)
    if doc.needs_pass:
        raise PIIError("PDF đang đặt mật khẩu.")
    warns, scanned = [], 0
    lang = ocr_lang()
    font_file = _unicode_font()
    uni = pymupdf.Font(fontfile=font_file) if font_file else None

    for pno, page in enumerate(doc, 1):
        text, tp = page.get_text("text"), None
        if not text.strip() and mode == "mask" and lang:      # trang scan -> OCR
            try:
                tp = page.get_textpage_ocr(language=lang, dpi=300, full=True)
                text = page.get_text("text", textpage=tp)
            except Exception as e:
                warns.append(f"Trang {pno}: OCR lỗi ({e})")
        if not text.strip():
            scanned += 1
            continue
        if tp is not None:
            warns.append(f"Trang {pno}: trang scan, đã dùng OCR - OCR có thể đọc sai chữ/số, hãy kiểm tra kỹ trang này")
        spans, words = _page_spans(page, tp), page.get_text("words", textpage=tp)
        hits = []                      # (rect hit, chuoi moi, chuoi cu, loai)
        if mode == "mask":
            found = {}
            for s, e, typ in engine.detect(text):
                found.setdefault(text[s:e], typ)
            for value in sorted(found, key=len, reverse=True):
                rects = _find_rects(page, value, tp)
                if not rects:
                    warns.append(f"Trang {pno}: không định vị được '{value[:30]}' để che")
                    continue
                tok = engine.vault.token_for(found[value], value)
                hits += [(r, tok, value, found[value]) for r in rects]
        else:
            for rawtok in {m.group(0) for m in TOKEN_RE.finditer(text)}:
                m = TOKEN_RE.fullmatch(rawtok)
                val = engine.vault.lookup(f"[[{m.group(1)}_{m.group(2)}]]")
                if val is None:
                    engine.missing[f"[[{m.group(1)}_{m.group(2)}]]"] += 1
                    continue
                hits += [(r, val, rawtok, m.group(1)) for r in _find_rects(page, rawtok, tp)]
        jobs, placed = [], []
        for r, new, old, typ in hits:
            tight, base, z, col = _metrics(r, spans)
            if tp is not None:      # trang scan: xoa dung khung muc OCR (+le) de khong sot net chu
                tight = pymupdf.Rect(r.x0 - 1.5, r.y0 - 2, r.x1 + 1.5, r.y1 + 2)
            if any((tight & q).get_area() > 0.5 * tight.get_area() for q in placed):
                continue                # trung voi o da che (vd. ten nam trong dia chi)
            placed.append(tight)
            jobs.append((tight, base, z, col, new, old))
            engine.stats[typ] += 1
        if not jobs:
            continue
        before = _chars(text)
        for tight, *_ in jobs:
            page.add_redact_annot(tight, fill=False)
        _apply_redactions(page, pixels=tp is not None)
        expected = before.copy()
        for job in jobs:
            expected.subtract(_chars(job[5]))
        lost = 0 if tp is not None else sum((+(expected - _chars(page.get_text("text")))).values())
        if lost:
            warns.append(f"Trang {pno}: có thể mất ~{lost} ký tự lân cận (font có khung chữ quá cao) - hãy kiểm tra lại")
        for tight, base, z, col, new, old in jobs:
            fs = min(z, 14.0)
            if mode == "restore":
                near = Counter()
                for sp in spans:
                    if abs(sp["origin"][1] - base) < 1.5 and "[[" not in sp["text"]:
                        near[round(sp["size"], 2)] += len(sp["text"])
                if near:
                    fs = min(near.most_common(1)[0][0], 14.0)
            if mode == "restore" and uni:
                nxt = [w[0] for w in words if abs(w[3] - tight.y1) < z * 1.2 and w[0] >= tight.x1 - 0.5]
                limit = max(tight.width, (min(nxt) if nxt else page.rect.x1 - 18) - 2 - tight.x0)
                while fs > 6 and uni.text_length(new, fontsize=fs) > limit:
                    fs -= 0.25
                page.insert_text((tight.x0, base), new, fontsize=fs, fontname="uni", fontfile=font_file, color=col)
            else:
                if mode == "restore":   # khong co font Unicode -> bo dau de khong mat chu
                    import unicodedata
                    new = unicodedata.normalize("NFKD", new).encode("ascii", "ignore").decode()
                while fs > 3.5 and pymupdf.get_text_length(new, fontname="helv", fontsize=fs) > tight.width:
                    fs -= 0.25          # thu nho cho vua cho cu de khong de len chu ben canh
                page.insert_text((tight.x0, base), new, fontname="helv", fontsize=fs, color=col)
        if tp is not None:      # lop chu an cho phan con lai cua trang scan (tim kiem / AI doc duoc); bo phan da che
            for w in words:
                wr = pymupdf.Rect(w[:4])
                if not w[4].strip() or any((wr & q).get_area() > 0 for q in placed):
                    continue
                kw = dict(fontname="uni", fontfile=font_file) if font_file else dict(fontname="helv")
                page.insert_text((wr.x0, wr.y1 - wr.height * 0.2), w[4], fontsize=max(wr.height * 0.8, 3),
                                 render_mode=3, **kw)
    if scanned:
        warns.append(f"{scanned}/{doc.page_count} trang là ảnh scan không xử lý được "
                     + ("(OCR không đọc ra chữ)." if lang else "(chưa có gói OCR: cần thư mục tessdata có eng/vie.traineddata)."))
    if mode == "mask":
        doc.set_metadata({})
        try:
            doc.del_xml_metadata()
        except Exception:
            pass
    doc.save(dst, garbage=4, deflate=True)
    doc.close()
    return warns


# --------------------------------------------------------------------------
# TEXT
# --------------------------------------------------------------------------
IMG_EXT = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}
TEXT_EXT = {".txt", ".md", ".json", ".html", ".htm", ".xml", ".log"}


def process_text(src, dst, engine, mode):
    text = read_text_file(src)
    spans = engine.mask_spans(text) if mode == "mask" else engine.restore_spans(text)
    with open(dst, "w", encoding="utf-8", newline="") as f:
        f.write(apply_spans(text, spans))
    return []


# --------------------------------------------------------------------------
# EXCEL (.xlsx/.xlsm; .xls cu duoc doi qua Excel) va CSV
#   - che theo TIEU DE COT (Ho ten / SDT / Dia chi / Email / STK / CCCD / MST / Ngay sinh): ca cot duoc che
#   - ngoai ra o chu nao cung duoc quet bang nhan dang thong thuong
# --------------------------------------------------------------------------
import csv
import io
import unicodedata

M = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
_C, _V, _IS, _T, _F, _SI, _ROW, _RPH = (f"{{{M}}}{x}" for x in ("c", "v", "is", "t", "f", "si", "row", "rPh"))
_AP, _AT = f"{{{A}}}p", f"{{{A}}}t"
_XL_SHEET = re.compile(r"^xl/worksheets/[^/]+\.xml$")
_XL_COMMENT = re.compile(r"^xl/(comments|threadedComments)[^/]*(/[^/]+)?\.xml$")
_XL_DRAW = re.compile(r"^xl/(drawings|charts)/[^/]+\.xml$")

_HDR = [
    ("EMAIL", r"\be-?mail\b|\bmail\b"),
    ("ID", r"\bcccd\b|\bcmnd\b|\bcmt\b|can cuoc|ho chieu|passport|dinh danh"),
    ("TAX", r"\bmst\b|ma so thue|\btax\b"),
    ("BANK", r"\bstk\b|so tai khoan|tai khoan|\baccount\b|so tk"),
    ("DOB", r"ngay sinh|\bdob\b|date of birth|sinh nhat"),
    ("PHONE", r"dien thoai|\bsdt\b|\bso dt\b|\bphone\b|\bmobile\b|\btel\b|hotline|di dong|so may"),
    ("ADDR", r"dia chi|\baddress\b|noi o|que quan|thuong tru"),
    ("NAME", r"ho ten|ho va ten|\bten (?:khach hang|kh|nhan vien|nv|nguoi)|nguoi (?:lien he|dai dien|nhan|gui)|"
             r"full ?name|customer name|^nhan vien$|^khach hang$"),
]


def _plain(s):
    s = unicodedata.normalize("NFD", s.replace("đ", "d").replace("Đ", "D"))
    return " ".join("".join(c for c in s if unicodedata.category(c) != "Mn").lower().split())


def header_type(text, enabled):
    t = _plain(text)
    if not t or len(t) > 40:
        return None
    for typ, rx in _HDR:
        if typ in enabled and re.search(rx, t):
            return typ
    return None


def find_header(rows, enabled):
    """rows: [(so_dong, {cot: chu})] -> (so_dong_tieu_de, {cot: loai}) hoac (None, {})."""
    first = None
    for rn, cells in rows[:20]:
        cols = {c: header_type(t, enabled) for c, t in cells.items()}
        cols = {c: t for c, t in cols.items() if t}
        if len(cols) >= 2:
            return rn, cols
        if cols and first is None:
            first = (rn, cols)
    return first or (None, {})


def _col_idx(ref):
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group():
        n = n * 26 + ord(ch) - 64
    return n


def _num_str(v):
    try:
        f = float(v)
        return str(int(f)) if f == int(f) and abs(f) < 1e18 else v
    except ValueError:
        return v


def _cell_text(c, ss):
    """(chu, loai) cua o: loai = 's' | 'inline' | 'num' ; (None, None) neu rong / cong thuc."""
    if c.find(_F) is not None:
        return None, None
    t, v = c.get("t"), c.find(_V)
    if t == "s":
        return (ss[int(v.text)] if v is not None and v.text else None), "s"
    if t == "inlineStr":
        return "".join(x.text or "" for x in c.iter(_T)), "inline"
    if t in (None, "n") and v is not None and v.text:
        return _num_str(v.text.strip()), "num"
    return None, None


def _set_inline(c, text):
    for ch in list(c):
        if ch.tag in (_V, _IS):
            c.remove(ch)
    c.set("t", "inlineStr")
    etree.SubElement(etree.SubElement(c, _IS), _T).text = text


def _blocks(root, block_tag, t_tag, engine, mode):
    """Che/khoi phuc theo tung khoi chu (doan van) - dung chung cho shared strings, comment, drawing."""
    for blk in root.iter(block_tag):
        ts = [t for t in blk.iter(t_tag)]
        full = "".join(t.text or "" for t in ts)
        if not full.strip() or (mode == "restore" and "[" not in full):
            continue
        spans = engine.mask_spans(full) if mode == "mask" else engine.restore_spans(full)
        if spans:
            _rewrite(ts, spans)


def _xl_sheet(root, ss, engine, mode, used):
    rows = []
    for row in root.iter(_ROW):
        rn = int(row.get("r") or len(rows) + 1)
        cells = {}
        for c in row.findall(_C):
            txt, kind = _cell_text(c, ss)
            if kind in ("s", "inline") and txt:
                cells[_col_idx(c.get("r"))] = txt
        rows.append((rn, cells))
    hdr_rn, cols = find_header(rows, engine.enabled) if mode == "mask" else (None, {})

    for row in root.iter(_ROW):
        rn = int(row.get("r") or 0)
        for c in row.findall(_C):
            txt, kind = _cell_text(c, ss)
            if txt is None or not txt.strip():
                continue
            col = _col_idx(c.get("r"))
            typ = cols.get(col) if (hdr_rn is not None and rn > hdr_rn) else None
            if mode == "mask":
                if typ and not (kind == "num" and typ == "DOB") and not TOKEN_RE.fullmatch(txt.strip()):
                    _set_inline(c, engine.vault.token_for(typ, txt.strip()))
                    engine.stats[typ] += 1
                    continue
                if kind == "num":
                    if "ID" in engine.enabled and re.fullmatch(r"\d{12}", txt):
                        _set_inline(c, engine.vault.token_for("ID", txt))
                        engine.stats["ID"] += 1
                    continue
                if kind == "inline":
                    ts = list(c.iter(_T))
                    spans = engine.mask_spans("".join(t.text or "" for t in ts))
                    if spans:
                        _rewrite(ts, spans)
            elif kind == "inline":
                ts = list(c.iter(_T))
                spans = engine.restore_spans("".join(t.text or "" for t in ts))
                if spans:
                    _rewrite(ts, spans)
    if mode == "mask":      # ghi nho cac shared string con duoc dung
        for c in root.iter(_C):
            if c.get("t") == "s" and c.find(_V) is not None and c.find(_V).text:
                used.add(int(c.find(_V).text))


def _parse(data):
    return etree.fromstring(data, etree.XMLParser(resolve_entities=False, huge_tree=True))


def _dump(root):
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


def process_xlsx(src, dst, engine, mode):
    try:
        zin = zipfile.ZipFile(src)
    except zipfile.BadZipFile:
        raise PIIError("File Excel không đọc được (có thể đang đặt mật khẩu / hỏng).")
    with zin:
        items = zin.infolist()
        data = {i.filename: zin.read(i.filename) for i in items}
    ss = []
    if "xl/sharedStrings.xml" in data:
        sroot = _parse(data["xl/sharedStrings.xml"])
        for rp in list(sroot.iter(_RPH)):          # chu phien am (furigana) - bo
            rp.getparent().remove(rp)
        ss = ["".join(t.text or "" for t in si.iter(_T)) for si in sroot.findall(_SI)]
    used: set = set()
    for name in list(data):
        if _XL_SHEET.match(name):
            root = _parse(data[name])
            _xl_sheet(root, ss, engine, mode, used)
            data[name] = _dump(root)
    if ss:
        for i, si in enumerate(sroot.findall(_SI)):
            ts = list(si.iter(_T))
            full = "".join(t.text or "" for t in ts)
            if mode == "mask" and i not in used:     # chuoi chi con duoc cot-da-che dung -> xoa han
                for t in ts:
                    t.text = ""
                continue
            if not full.strip() or (mode == "restore" and "[" not in full):
                continue
            spans = engine.mask_spans(full) if mode == "mask" else engine.restore_spans(full)
            if spans:
                _rewrite(ts, spans)
        data["xl/sharedStrings.xml"] = _dump(sroot)
    for name in list(data):
        if _XL_COMMENT.match(name):
            root = _parse(data[name])
            _blocks(root, f"{{{M}}}text", _T, engine, mode)
            if mode == "mask":
                for a in root.iter(f"{{{M}}}author"):
                    a.text = "Author"
            data[name] = _dump(root)
        elif _XL_DRAW.match(name):
            root = _parse(data[name])
            _blocks(root, _AP, _AT, engine, mode)
            data[name] = _dump(root)
        elif name.endswith(".rels"):
            data[name] = _docx_rels(data[name], engine, mode)
        elif mode == "mask" and name in ("docProps/core.xml", "docProps/app.xml"):
            data[name] = _scrub_props(data[name])
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for i in items:
            zout.writestr(i, data[i.filename])
    return []


def read_text_file(path):
    raw = open(path, "rb").read()
    for enc in ("utf-8-sig", "utf-16", "cp1258", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeError:
            continue
    return raw.decode("utf-8", "replace")


def process_csv(src, dst, engine, mode):
    text = read_text_file(src)
    if src.lower().endswith(".tsv"):
        delim = "\t"
    else:
        try:
            delim = csv.Sniffer().sniff(text[:5000], delimiters=",;\t|").delimiter
        except csv.Error:
            delim = ","
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
    if mode == "mask":
        hdr, cols = find_header([(i, dict(enumerate(r))) for i, r in enumerate(rows)], engine.enabled)
    else:
        hdr, cols = None, {}
    for ri, row in enumerate(rows):
        for ci, cell in enumerate(row):
            if not cell.strip():
                continue
            typ = cols.get(ci) if (hdr is not None and ri > hdr) else None
            if mode == "mask":
                if typ and not TOKEN_RE.fullmatch(cell.strip()):
                    row[ci] = engine.vault.token_for(typ, cell.strip())
                    engine.stats[typ] += 1
                else:
                    row[ci] = apply_spans(cell, engine.mask_spans(cell))
            else:
                row[ci] = apply_spans(cell, engine.restore_spans(cell))
    with open(dst, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f, delimiter=delim, lineterminator="\r\n").writerows(rows)
    return []


# --------------------------------------------------------------------------
# DIEU PHOI
# --------------------------------------------------------------------------
def out_path(src, mode, out_dir=None):
    base, ext = os.path.splitext(os.path.basename(src))
    ext = {".doc": ".docx", ".xls": ".xlsx", ".png": ".pdf", ".jpg": ".pdf", ".jpeg": ".pdf",
           ".tif": ".pdf", ".tiff": ".pdf", ".bmp": ".pdf"}.get(ext.lower(), ext)
    if mode == "mask":
        name = f"{base}.masked{ext}"
    else:
        base = re.sub(r"\.masked$", "", base, flags=re.I)
        name = f"{base}.restored{ext}"
    return os.path.join(out_dir or os.path.dirname(os.path.abspath(src)), name)


def process_file(src, mode, engine, out_dir=None):
    """mode = 'mask' | 'restore'. Tra ve (duong dan ket qua, danh sach canh bao)."""
    ext = os.path.splitext(src)[1].lower()
    dst = out_path(src, mode, out_dir)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    tmp_dir = None
    try:
        if ext in (".doc", ".xls"):
            src = doc_to_docx(src)
            tmp_dir = os.path.dirname(src)
            ext = os.path.splitext(src)[1].lower()
        if ext in (".docx", ".docm"):
            warns = process_docx(src, dst, engine, mode)
        elif ext in (".xlsx", ".xlsm"):
            warns = process_xlsx(src, dst, engine, mode)
        elif ext in (".csv", ".tsv"):
            warns = process_csv(src, dst, engine, mode)
        elif ext == ".pdf":
            warns = process_pdf(src, dst, engine, mode)
        elif ext in IMG_EXT:
            if mode != "mask":
                raise PIIError("Ảnh chỉ che được (ra file PDF .masked.pdf); khôi phục hãy dùng file PDF đó.")
            if pymupdf is None:
                raise PIIError("Thiếu thư viện PyMuPDF (pip install pymupdf).")
            tmp_dir = tempfile.mkdtemp(prefix="pii_")
            tmp_pdf = os.path.join(tmp_dir, "scan.pdf")
            with open(tmp_pdf, "wb") as f:
                f.write(pymupdf.open(src).convert_to_pdf())
            warns = process_pdf(tmp_pdf, dst, engine, mode)
        elif ext in TEXT_EXT:
            warns = process_text(src, dst, engine, mode)
        else:
            raise PIIError(f"Chưa hỗ trợ định dạng {ext}")
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    engine.vault.save()
    return dst, warns


def summarize(engine):
    parts = [f"{TYPE_LABELS.get(k, 'Từ khóa riêng' if k == 'CUSTOM' else k)}: {v}"
             for k, v in sorted(engine.stats.items())]
    return ", ".join(parts) if parts else "(không có gì)"


# --------------------------------------------------------------------------
# DONG LENH
# --------------------------------------------------------------------------
def cli(argv):
    ap = argparse.ArgumentParser(description="Che / khôi phục thông tin cá nhân trong .doc .docx .pdf .txt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("mask", "restore"):
        p = sub.add_parser(name, help="che" if name == "mask" else "khôi phục")
        p.add_argument("files", nargs="+")
        p.add_argument("--out", help="thư mục xuất (mặc định: cạnh file gốc)")
        if name == "mask":
            p.add_argument("--term", action="append", default=[], help="từ khóa riêng cần che (lặp được)")
            p.add_argument("--terms-file", help="file txt, mỗi dòng 1 từ khóa riêng")
            p.add_argument("--skip", default="", help="bỏ qua loại: " + ",".join(DEFAULT_TYPES))
    v = sub.add_parser("vault", help="xem vault")
    v.add_argument("--reveal", action="store_true", help="hiện cả giá trị thật")
    for p in sub.choices.values():
        p.add_argument("--vault", default=DEFAULT_VAULT)
        p.add_argument("--password", action="store_true", help="hỏi mật khẩu vault (mã hóa vault)")
    a = ap.parse_args(argv)

    pw = os.environ.get("PII_SHIELD_PASSWORD")
    if a.password and not pw:
        pw = getpass.getpass("Mật khẩu vault: ")
    vault = Vault(a.vault, pw)

    if a.cmd == "vault":
        print(f"{len(vault.items)} mục trong {a.vault}")
        for t, v in vault.items.items():
            print(t, "=", v["value"] if a.reveal else "*" * min(len(v["value"]), 8))
        return 0

    terms = list(getattr(a, "term", []) or [])
    if getattr(a, "terms_file", None):
        terms += [l.strip() for l in open(a.terms_file, encoding="utf-8") if l.strip()]
    skip = {s.strip().upper() for s in getattr(a, "skip", "").split(",") if s.strip()}
    engine = Engine(vault, [t for t in DEFAULT_TYPES if t not in skip], terms)
    rc = 0
    for f in a.files:
        before = Counter(engine.stats)
        try:
            dst, warns = process_file(f, a.cmd, engine, a.out)
        except Exception as e:
            print(f"[LỖI] {f}: {e}")
            rc = 1
            continue
        print(f"[OK] {f}\n     -> {dst}")
        for w in warns:
            print("     !", w)
    print("Tổng:", summarize(engine))
    if engine.missing:
        print("Token không có trong vault:", ", ".join(engine.missing))
    return rc


# --------------------------------------------------------------------------
# GIAO DIEN
# --------------------------------------------------------------------------
def gui():
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    dnd = False
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        root = TkinterDnD.Tk()
        dnd = True
    except Exception:
        root = tk.Tk()
    root.title("PII Shield - Che / Khôi phục thông tin cá nhân")
    root.geometry("820x760")
    q: "queue.Queue[str]" = queue.Queue()
    files: list[str] = []

    pad = {"padx": 8, "pady": 4}
    # --- file ---
    f1 = ttk.LabelFrame(root, text="1. File cần xử lý (.doc .docx .xls .xlsx .pdf scan/ảnh .csv .txt)")
    f1.pack(fill="x", **pad)
    lb = tk.Listbox(f1, height=6, selectmode="extended")
    lb.pack(side="left", fill="both", expand=True, padx=6, pady=6)
    bf = ttk.Frame(f1)
    bf.pack(side="right", padx=6)

    def add_files(paths):
        for p in paths:
            if p and p not in files:
                files.append(p)
                lb.insert("end", p)

    def pick():
        add_files(filedialog.askopenfilenames(filetypes=[("Tài liệu", "*.doc *.docx *.xls *.xlsx *.pdf *.png *.jpg *.jpeg *.tif *.csv *.txt *.md"),
                                                         ("Tất cả", "*.*")]))

    def clear():
        files.clear()
        lb.delete(0, "end")

    ttk.Button(bf, text="Thêm file…", command=pick).pack(fill="x", pady=2)
    ttk.Button(bf, text="Xóa danh sách", command=clear).pack(fill="x", pady=2)
    if dnd:
        lb.drop_target_register(DND_FILES)
        lb.dnd_bind("<<Drop>>", lambda e: add_files(root.tk.splitlist(e.data)))
        ttk.Label(f1, text="(kéo thả file vào đây cũng được)").pack(side="bottom")

    # --- loai thong tin ---
    f2 = ttk.LabelFrame(root, text="2. Loại thông tin cần che")
    f2.pack(fill="x", **pad)
    vars_ = {}
    for i, (k, label) in enumerate(TYPE_LABELS.items()):
        vars_[k] = tk.BooleanVar(value=True)
        ttk.Checkbutton(f2, text=label, variable=vars_[k]).grid(row=i // 3, column=i % 3, sticky="w", padx=8, pady=2)

    f3 = ttk.LabelFrame(root, text="3. Từ khóa riêng cần che (mỗi dòng 1 cụm: tên người, tên công ty, tên dự án...)")
    f3.pack(fill="x", **pad)
    terms_box = tk.Text(f3, height=4)
    terms_box.pack(fill="x", padx=6, pady=6)

    # --- vault ---
    f4 = ttk.LabelFrame(root, text="4. Vault (nơi lưu bảng đối chiếu để khôi phục) & thư mục xuất")
    f4.pack(fill="x", **pad)
    vault_var, pw_var, out_var = tk.StringVar(value=DEFAULT_VAULT), tk.StringVar(), tk.StringVar()
    ttk.Label(f4, text="Vault:").grid(row=0, column=0, sticky="e")
    ttk.Entry(f4, textvariable=vault_var, width=62).grid(row=0, column=1, padx=4, pady=2)
    ttk.Button(f4, text="Chọn…", command=lambda: vault_var.set(
        filedialog.asksaveasfilename(defaultextension=".json", initialfile="pii_vault.json",
                                     confirmoverwrite=False) or vault_var.get())).grid(row=0, column=2)
    ttk.Label(f4, text="Mật khẩu (tùy chọn):").grid(row=1, column=0, sticky="e")
    ttk.Entry(f4, textvariable=pw_var, show="•", width=30).grid(row=1, column=1, sticky="w", padx=4, pady=2)
    ttk.Label(f4, text="Thư mục xuất:").grid(row=2, column=0, sticky="e")
    ttk.Entry(f4, textvariable=out_var, width=62).grid(row=2, column=1, padx=4, pady=2)
    ttk.Button(f4, text="Chọn…", command=lambda: out_var.set(filedialog.askdirectory() or out_var.get())
               ).grid(row=2, column=2)
    ttk.Label(f4, text="(để trống = lưu cạnh file gốc)").grid(row=3, column=1, sticky="w")

    # --- nut ---
    bar = ttk.Frame(root)
    bar.pack(fill="x", **pad)
    log = tk.Text(root, height=12, state="disabled", wrap="word")

    def say(msg):
        q.put(msg)

    def work(mode):
        try:
            vault = Vault(vault_var.get(), pw_var.get() or None)
            terms = [t for t in terms_box.get("1.0", "end").splitlines() if t.strip()]
            engine = Engine(vault, [k for k, v in vars_.items() if v.get()], terms)
            for f in list(files):
                try:
                    dst, warns = process_file(f, mode, engine, out_var.get() or None)
                    say(f"✔ {os.path.basename(f)}  →  {dst}")
                    for w in warns:
                        say(f"   ! {w}")
                except Exception as e:
                    say(f"✘ {os.path.basename(f)}: {e}")
            say(f"Tổng: {summarize(engine)}")
            if engine.missing:
                say("⚠ Token không có trong vault: " + ", ".join(engine.missing))
        except Exception as e:
            say(f"✘ {e}")
        say("— xong —")

    def run(mode):
        if not files:
            messagebox.showinfo("PII Shield", "Chưa chọn file nào.")
            return
        threading.Thread(target=work, args=(mode,), daemon=True).start()

    ttk.Button(bar, text="🔒  CHE THÔNG TIN", command=lambda: run("mask")).pack(side="left", expand=True, fill="x", padx=4)
    ttk.Button(bar, text="🔓  KHÔI PHỤC", command=lambda: run("restore")).pack(side="left", expand=True, fill="x", padx=4)
    log.pack(fill="both", expand=True, **pad)

    def pump():
        while not q.empty():
            log.config(state="normal")
            log.insert("end", q.get() + "\n")
            log.see("end")
            log.config(state="disabled")
        root.after(150, pump)

    pump()
    root.mainloop()


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if len(sys.argv) > 1:
        sys.exit(cli(sys.argv[1:]))
    gui()
