"""
Free Fire JWT auto-refresh — Vercel friendly (in-memory cache).
Needs guest uid + password in accounts.json (read-only on Vercel).
Flow: OAuth guest grant -> MajorLogin -> JWT (kept in memory)
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MAIN_KEY = b"Yg&tc%DEuh6%Zc^8"
MAIN_IV = b"6oyZDr22E3ychjM%"

CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
CLIENT_ID = "100067"

OAUTH_URL = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
MAJOR_LOGIN_URLS = {
    "IND": "https://loginbp.ggbluefox.com/MajorLogin",
    "BD": "https://loginbp.ggpolarbear.com/MajorLogin",
    "BR": "https://loginbp.ggredtree.com/MajorLogin",
    "US": "https://loginbp.ggredtree.com/MajorLogin",
    "SAC": "https://loginbp.ggredtree.com/MajorLogin",
    "NA": "https://loginbp.ggredtree.com/MajorLogin",
    "DEFAULT": "https://loginbp.ggpolarbear.com/MajorLogin",
}

USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)"
RELEASE_VERSION = "OB55"
EXPIRY_MARGIN_SEC = 30 * 60

_lock = threading.Lock()
_memory_tokens: Dict[str, List[Dict[str, Any]]] = {}
_last_refresh: Dict[str, float] = {}


def _token_path(region: str) -> str:
    region = (region or "BD").upper()
    if region == "IND":
        name = "token_ind.json"
    elif region in {"BR", "US", "SAC", "NA"}:
        name = "token_br.json"
    else:
        name = "token_bd.json"
    return os.path.join(BASE_DIR, name)


def _accounts_path() -> str:
    return os.path.join(BASE_DIR, "accounts.json")


def load_accounts() -> List[Dict[str, str]]:
    path = _accounts_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        out = []
        for a in data:
            uid = str(a.get("uid", "")).strip()
            password = str(a.get("password", "")).strip()
            if not uid or not password or uid.startswith("REPLACE_"):
                continue
            out.append({
                "uid": uid,
                "password": password,
                "region": str(a.get("region", "BD")).upper(),
            })
        return out
    except Exception:
        return []


def jwt_exp(token: str) -> Optional[int]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1]
        pad = "=" * ((4 - len(payload) % 4) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload + pad))
        exp = data.get("exp")
        return int(exp) if exp is not None else None
    except Exception:
        return None


def token_is_valid(token: str, margin: int = EXPIRY_MARGIN_SEC) -> bool:
    exp = jwt_exp(token)
    if exp is None:
        return False
    return exp > (time.time() + margin)


def _read_file_tokens(region: str) -> List[Dict[str, Any]]:
    path = _token_path(region)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _try_write_file(region: str, tokens: List[Dict[str, Any]]) -> bool:
    try:
        path = _token_path(region)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        return True
    except Exception:
        return False


def get_memory_tokens(region: str) -> List[Dict[str, Any]]:
    region = (region or "BD").upper()
    with _lock:
        return list(_memory_tokens.get(region, []))


def set_memory_tokens(region: str, tokens: List[Dict[str, Any]]) -> None:
    region = (region or "BD").upper()
    with _lock:
        _memory_tokens[region] = list(tokens)
        _last_refresh[region] = time.time()


def get_access_token(uid: str, password: str) -> Tuple[str, str]:
    payload = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": CLIENT_SECRET,
        "client_id": CLIENT_ID,
    }
    headers = {
        "User-Agent": USER_AGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    r = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=20)
    r.raise_for_status()
    data = r.json()
    access = data.get("access_token") or data.get("accessToken") or "0"
    open_id = data.get("open_id") or data.get("openId") or "0"
    return str(access), str(open_id)


def _aes_encrypt(data: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def major_login_jwt(access_token: str, open_id: str, region: str = "BD") -> Optional[str]:
    region = (region or "BD").upper()
    url = MAJOR_LOGIN_URLS.get(region, MAJOR_LOGIN_URLS["DEFAULT"])

    def _encode_varint(n: int) -> bytes:
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                break
        return bytes(out)

    def _encode_string(field_no: int, s: str) -> bytes:
        b = s.encode("utf-8")
        return bytes([(field_no << 3) | 2]) + _encode_varint(len(b)) + b

    def _encode_int32(field_no: int, v: int) -> bytes:
        return bytes([(field_no << 3) | 0]) + _encode_varint(v)

    body = b""
    body += _encode_string(1, open_id)
    body += _encode_int32(2, 4)
    body += _encode_string(3, access_token)
    body += _encode_int32(4, 4)
    encrypted = _aes_encrypt(body)

    headers = {
        "User-Agent": USER_AGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": RELEASE_VERSION,
    }

    try:
        r = requests.post(url, data=encrypted, headers=headers, timeout=25, verify=False)
        text = r.text or ""
        if "eyJ" in text:
            start = text.find("eyJ")
            end = start
            while end < len(text) and text[end] not in " \n\r\t\"'<>":
                end += 1
            jwt = text[start:end].strip()
            if jwt.count(".") >= 2:
                return jwt
        try:
            data = r.json()
            for k in ("token", "jwt", "access_token", "lock_token"):
                if isinstance(data.get(k), str) and data[k].startswith("eyJ"):
                    return data[k]
        except Exception:
            pass
        content = r.content or b""
        if b"eyJ" in content:
            i = content.find(b"eyJ")
            j = i
            while j < len(content) and content[j] not in b" \n\r\t\"'<>":
                j += 1
            jwt = content[i:j].decode("utf-8", errors="ignore")
            if jwt.count(".") >= 2:
                return jwt
    except Exception:
        return None
    return None


def generate_jwt_for_account(uid: str, password: str, region: str = "BD") -> Optional[str]:
    try:
        access, open_id = get_access_token(uid, password)
        if not access or access == "0" or not open_id or open_id == "0":
            return None
        return major_login_jwt(access, open_id, region=region)
    except Exception:
        return None


def valid_from_list(tokens: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for t in tokens:
        if not isinstance(t, dict):
            continue
        tok = str(t.get("token", ""))
        if tok.startswith("eyJ") and token_is_valid(tok):
            out.append({"token": tok, "uid": t.get("uid")})
    return out


def refresh_region(region: str, force: bool = False) -> List[Dict[str, Any]]:
    region = (region or "BD").upper()

    if not force:
        mem = valid_from_list(get_memory_tokens(region))
        if mem:
            return mem
        file_valid = valid_from_list(_read_file_tokens(region))
        if file_valid:
            set_memory_tokens(region, file_valid)
            return file_valid

    accounts = [a for a in load_accounts() if a["region"] == region]
    if not accounts:
        accounts = load_accounts()

    new_tokens: List[Dict[str, Any]] = []
    for acc in accounts:
        jwt = generate_jwt_for_account(acc["uid"], acc["password"], region=acc.get("region", region))
        if jwt and token_is_valid(jwt, margin=0):
            new_tokens.append({"token": jwt, "uid": acc["uid"]})

    if new_tokens:
        set_memory_tokens(region, new_tokens)
        _try_write_file(region, new_tokens)
        return new_tokens

    mem = get_memory_tokens(region) or _read_file_tokens(region)
    return mem


def ensure_tokens(region: str) -> List[Dict[str, Any]]:
    region = (region or "BD").upper()
    valid = valid_from_list(get_memory_tokens(region))
    if valid:
        return valid
    valid = valid_from_list(_read_file_tokens(region))
    if valid:
        set_memory_tokens(region, valid)
        return valid
    return refresh_region(region, force=True)


def refresh_all(force: bool = False) -> Dict[str, int]:
    accounts = load_accounts()
    regions = sorted({a["region"] for a in accounts}) or ["BD"]
    result = {}
    for reg in regions:
        toks = refresh_region(reg, force=force)
        result[reg] = len([t for t in toks if token_is_valid(str(t.get("token", "")), margin=0)])
    return result


if __name__ == "__main__":
    print("Accounts:", len(load_accounts()))
    print(refresh_all(force=True))
