from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import aiohttp
import requests
import json
import os
import like_pb2
import uid_generator_pb2
import visit_count_pb2
from google.protobuf.message import DecodeError
from collections import OrderedDict

try:
    from token_refresh import ensure_tokens, refresh_all, load_accounts, token_is_valid
except Exception:
    ensure_tokens = None
    refresh_all = None
    load_accounts = None
    token_is_valid = None

app = Flask(__name__)


# ---- CORS: allow the website (any origin, incl. local file) to call this API ----
@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Accept, Authorization"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp


@app.route("/like", methods=["OPTIONS"])
@app.route("/remain", methods=["OPTIONS"])
@app.route("/refresh", methods=["OPTIONS"])
@app.route("/token-status", methods=["OPTIONS"])
def cors_preflight():
    return ("", 204)


# API key(s)
VALID_API_KEYS = {
    "SyroxCheat",
}

# Like limit (in-memory; resets on restart)
daily_limit = 20
used_count = 0

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_tokens(region):
    """
    Load tokens for region.
    Auto-refresh via token_refresh.ensure_tokens() when accounts.json has guest uid/password.
    Falls back to existing token_*.json files.
    """
    region = (region or "").upper()
    try:
        # 1) try auto refresh / valid tokens
        if ensure_tokens is not None:
            tokens = ensure_tokens(region)
            if tokens:
                # keep only entries that look like JWT
                cleaned = []
                for t in tokens:
                    tok = t.get("token") if isinstance(t, dict) else None
                    if tok and isinstance(tok, str) and tok.startswith("eyJ"):
                        cleaned.append({"token": tok})
                if cleaned:
                    return cleaned

        # 2) plain file fallback
        if region == "IND":
            path = os.path.join(BASE_DIR, "token_ind.json")
        elif region in {"BR", "US", "SAC", "NA"}:
            path = os.path.join(BASE_DIR, "token_br.json")
        else:
            path = os.path.join(BASE_DIR, "token_bd.json")

        if not os.path.exists(path) or os.path.getsize(path) == 0:
            path = os.path.join(BASE_DIR, "token_bd.json")

        with open(path, "r", encoding="utf-8") as f:
            tokens = json.load(f)

        if not tokens or not isinstance(tokens, list):
            app.logger.error(f"No tokens found for region {region}")
            return None
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for region {region}: {e}")
        return None


def encrypt_message(plaintext):
    try:
        key = b"Yg&tc%DEuh6%Zc^8"
        iv = b"6oyZDr22E3ychjM%"
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode("utf-8")
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None


def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None


async def send_request(encrypted_uid, token, url):
    try:
        edata = bytes.fromhex(encrypted_uid)
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB55",
        }
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=edata, headers=headers, ssl=False) as response:
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None


async def send_multiple_requests(uid, region, url, max_requests=50):
    try:
        protobuf_message = create_protobuf_message(uid, region)
        if protobuf_message is None:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if encrypted_uid is None:
            return None
        tokens = load_tokens(region)
        if tokens is None or len(tokens) == 0:
            return None

        tasks = []
        # limit parallel calls to avoid hammering
        count = min(max_requests, max(len(tokens) * 10, 10))
        for i in range(count):
            token = tokens[i % len(tokens)]["token"]
            tasks.append(send_request(encrypted_uid, token, url))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None


def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None


def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    return encrypt_message(protobuf_data)


def make_request(encrypt, region, token):
    try:
        region = (region or "").upper()
        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypt)
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB55",
        }
        # Verify TLS certificates; do not silently decode an HTTP error page as protobuf.
        response = requests.post(url, data=edata, headers=headers, verify=True, timeout=20)
        if not response.ok:
            body_preview = (response.text or "")[:200].replace("\n", " ").replace("\r", " ")
            app.logger.error(
                "Player-info upstream HTTP %s; content-type=%s; body=%r",
                response.status_code,
                response.headers.get("Content-Type", "unknown"),
                body_preview,
            )
            return None
        if not response.content:
            app.logger.error("Player-info upstream returned an empty response (HTTP %s)", response.status_code)
            return None

        decoded = visit_count_pb2.Info()
        decoded.ParseFromString(response.content)
        # A successful protobuf parse should contain the expected account field.
        if not decoded.HasField("AccountInfo"):
            app.logger.error("Player-info response decoded but AccountInfo is missing")
            return None
        return decoded
    except DecodeError as e:
        app.logger.error("Player-info response was not a valid expected protobuf: %s", e)
        return None
    except requests.Timeout:
        app.logger.error("Player-info upstream request timed out")
        return None
    except requests.RequestException as e:
        app.logger.error("Player-info upstream network/TLS error: %s", e)
        return None
    except Exception as e:
        app.logger.exception("Unexpected error in make_request: %s", e)
        return None


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Syrox Free Fire Like API"}), 200


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "service": "Syrox Free Fire Like API",
        "endpoints": {
            "/like": "GET ?uid=&region=&key=",
            "/remain": "GET",
            "/refresh": "GET ?key=&force=1  (auto JWT from accounts.json)",
            "/token-status": "GET",
        },
        "status": "ok",
    })


@app.route("/like", methods=["GET"])
def handle_requests():
    global used_count

    api_key = request.args.get("key")
    if api_key not in VALID_API_KEYS:
        result = OrderedDict([
            ("error", "Invalid or missing API key"),
            ("status", 3),
        ])
        return app.response_class(
            response=json.dumps(result, separators=(",", ":")),
            status=401,
            mimetype="application/json",
        )

    uid = request.args.get("uid")
    region = (request.args.get("region") or "").upper()
    if not uid or not region:
        return jsonify({"error": "UID and region are required", "status": 4}), 400

    if not str(uid).isdigit():
        return jsonify({"error": "UID must be numeric", "status": 4}), 400

    try:
        tokens = load_tokens(region)
        if not tokens:
            raise Exception("Failed to load tokens. Add tokens to token_*.json")

        token = tokens[0]["token"]
        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            raise Exception("Encryption of UID failed.")

        before = make_request(encrypted_uid, region, token)
        if before is None:
            raise Exception(
                "Player-info lookup failed. Check Vercel logs for the upstream HTTP status, "
                "TLS/network error, or protobuf decode error. A JWT marked valid only means "
                "its expiry claim has not passed; it does not prove the game server accepts it."
            )

        before_like = before.AccountInfo.Likes

        if region == "IND":
            url = "https://client.ind.freefiremobile.com/LikeProfile"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/LikeProfile"
        else:
            url = "https://clientbp.ggpolarbear.com/LikeProfile"

        asyncio.run(send_multiple_requests(uid, region, url))

        after = make_request(encrypted_uid, region, token)
        if after is None:
            raise Exception("Final player-info lookup failed; check Vercel logs for the upstream response details.")

        after_like = after.AccountInfo.Likes
        like_given = after_like - before_like
        status = 1 if like_given > 0 else 2

        if status == 1:
            used_count += 1

        remaining = max(daily_limit - used_count, 0)

        result = OrderedDict([
            ("LikesGivenByAPI", like_given),
            ("LikesafterCommand", after_like),
            ("LikesbeforeCommand", before_like),
            ("PlayerNickname", after.AccountInfo.PlayerNickname),
            ("Level", after.AccountInfo.Levels),
            ("Region", after.AccountInfo.PlayerRegion),
            ("UID", after.AccountInfo.UID),
            ("status", status),
            ("daily_limit", daily_limit),
            ("used", used_count),
            ("remaining", remaining),
        ])

        return app.response_class(
            response=json.dumps(result, separators=(",", ":")),
            status=200,
            mimetype="application/json",
        )

    except Exception as e:
        app.logger.error(f"Error: {e}")
        return jsonify({"error": str(e), "status": 5}), 500


@app.route("/remain", methods=["GET"])
def remain_info():
    global used_count
    remaining = max(daily_limit - used_count, 0)
    data = {
        "daily_limit": daily_limit,
        "remaining": remaining,
        "used": used_count,
        "reset_info": "Resets on server restart (in-memory)",
    }
    return jsonify(data)


@app.route("/refresh", methods=["GET", "POST"])
def refresh_tokens_route():
    """
    Force refresh JWT tokens from accounts.json guest credentials.
    ?key=SyroxCheat&force=1
    """
    api_key = request.args.get("key") or (request.json or {}).get("key") if request.is_json else request.args.get("key")
    if api_key not in VALID_API_KEYS:
        return jsonify({"error": "Invalid or missing API key", "status": 3}), 401

    if refresh_all is None:
        return jsonify({
            "error": "token_refresh module not available",
            "hint": "Ensure token_refresh.py is deployed",
        }), 500

    force = str(request.args.get("force", "1")).lower() in {"1", "true", "yes"}
    accounts = load_accounts() if load_accounts else []
    if not accounts:
        return jsonify({
            "error": "No guest accounts configured",
            "hint": "Edit accounts.json with real uid + password (not REPLACE_ placeholders)",
            "status": 6,
        }), 400

    result = refresh_all(force=force)
    return jsonify({
        "status": 1,
        "refreshed": result,
        "accounts_loaded": len(accounts),
        "message": "Refresh finished. Check token_*.json",
    })


@app.route("/token-status", methods=["GET"])
def token_status():
    """Show whether current tokens are still valid (by JWT exp)."""
    regions = ["BD", "IND", "BR"]
    status = {}
    for reg in regions:
        path_map = {
            "IND": "token_ind.json",
            "BR": "token_br.json",
            "BD": "token_bd.json",
        }
        path = os.path.join(BASE_DIR, path_map[reg])
        items = []
        if os.path.exists(path) and os.path.getsize(path) > 0:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for t in data if isinstance(data, list) else []:
                    tok = t.get("token", "") if isinstance(t, dict) else ""
                    ok = token_is_valid(tok) if token_is_valid else None
                    items.append({"valid": ok, "preview": (tok[:20] + "...") if tok else ""})
            except Exception as e:
                items = [{"error": str(e)}]
        status[reg] = items
    accounts = load_accounts() if load_accounts else []
    return jsonify({
        "tokens": status,
        "accounts_configured": len(accounts),
        "validity_basis": "JWT expiry claim only; this does not confirm acceptance by the game server.",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
