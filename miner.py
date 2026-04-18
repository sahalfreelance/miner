#!/usr/bin/env python3
"""
Mine (minework.net) — AI Miner Bot
====================================
Otomatis crawl URL, bersihkan HTML, struktur JSON,
dan submit ke Mine WorkNet.

Pipeline:
  URL → Crawl HTML → Clean → Structure JSON → Submit

Cara pakai:
  1. Install awp-wallet:
       git clone https://github.com/awp-core/awp-wallet.git
       cd awp-wallet && bash install.sh

  2. Install deps Python:
       pip install requests beautifulsoup4 lxml

  3. Pilih AI backend GRATIS (salah satu):

     [A] Groq — gratis, daftar di console.groq.com (tanpa kartu kredit)
         export GROQ_API_KEY=gsk_xxxx

     [B] Ollama — gratis 100%, jalan lokal, tanpa akun
         install: https://ollama.com/download
         pull model: ollama pull llama3.2
         (tidak perlu set env var apapun)

     Jika keduanya tidak ada → fallback ke rule-based (tanpa AI)

  4. Set agent ID (opsional):
       export AWP_AGENT_ID=default

  5. Jalankan:
       python mine_miner.py
"""

import json
import os
import subprocess
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────
#  KONFIGURASI
# ─────────────────────────────────────────────

MINE_API       = "https://api.minework.net"              # WorkNet coordinator API
AGENT_ID       = os.getenv("AWP_AGENT_ID", "default")
SESSION_DUR    = 3600 * 8                             # 8 jam
HEARTBEAT_SEC  = 55                                   # kirim heartbeat tiap 55 detik
MIN_TASKS      = 80                                   # target minimum per epoch
MAX_TASKS      = 110                                  # batas aman (novice: 100)
SUBMIT_DELAY   = 2.0                                  # jeda antar submit (detik)
LOG_FILE       = "miner.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("mine-miner")


# ─────────────────────────────────────────────
#  WALLET HELPER
# ─────────────────────────────────────────────

class AWPWallet:
    def __init__(self, agent_id: str = "default"):
        self.agent_id = agent_id
        self.address: str | None = None

    def _run(self, *args) -> dict:
        cmd = ["awp-wallet", *args]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"awp-wallet error: {result.stderr.strip()}")
        return json.loads(result.stdout.strip())

    def unlock(self, duration: int = SESSION_DUR) -> str:
        data = self._run("unlock", "--duration", str(duration), "--scope", "full")
        token = data["sessionToken"]
        self.address = self.get_address()
        log.info(f"Wallet unlocked — {self.address}")
        return token

    def lock(self):
        try:
            self._run("lock")
        except Exception:
            pass
        log.info("Wallet locked.")

    def get_address(self) -> str:
        data = self._run("wallets")
        wallet_id = data["currentWalletId"]
        return data["wallets"][wallet_id]["address"]

    def sign_typed_data(self, typed_data: dict) -> str:
        """EIP-712 signing via awp-wallet sign-typed-data."""
        data_json = json.dumps(typed_data, separators=(",", ":"))
        resp = self._run("sign-typed-data", "--data", data_json)
        sig = resp.get("signature", "")
        if not sig:
            raise RuntimeError("sign-typed-data returned empty signature")
        return sig


# ─────────────────────────────────────────────
#  EIP-712 AUTH
# ─────────────────────────────────────────────

import secrets
import ssl
from urllib.parse import urlsplit
from requests.adapters import HTTPAdapter

# Signature config cache (diisi dari API)
_SIG_CONFIG: dict = {}

def _fetch_sig_config() -> dict:
    global _SIG_CONFIG
    if _SIG_CONFIG:
        return _SIG_CONFIG
    try:
        r = requests.get(f"{MINE_API}/api/public/v1/signature-config", timeout=10)
        if r.ok:
            _SIG_CONFIG = r.json().get("data", {})
            log.info(f"Signature config: chain_id={_SIG_CONFIG.get('chain_id')}, domain={_SIG_CONFIG.get('domain_name')}")
    except Exception as e:
        log.warning(f"Gagal fetch signature config: {e}")
    return _SIG_CONFIG


def _keccak256(data: bytes) -> bytes:
    """Keccak-256. Butuh: pip install pysha3"""
    import hashlib
    try:
        import sha3  # noqa — patches hashlib agar sha3_256 = Keccak-256
    except ImportError:
        log.warning("pysha3 tidak terinstall! Jalankan: pip install pysha3")
    h = hashlib.new("sha3_256")
    h.update(data)
    return h.digest()


def _keccak_hex(data: bytes) -> str:
    return "0x" + _keccak256(data).hex()


def _hash_body(body: Any, content_type: str) -> str:
    if body is None:
        return _keccak_hex(b"")
    s = json.dumps(body, separators=(",", ":"))
    return _keccak_hex(s.encode("utf-8"))


def _hash_query(url: str) -> str:
    query = urlsplit(url).query or ""
    return _keccak_hex(query.encode("utf-8"))


def _hash_headers(headers: dict, signed_headers: tuple) -> str:
    parts = [f"{h.lower()}:{headers.get(h.lower(), headers.get(h, ''))}" for h in signed_headers]
    return _keccak_hex("\n".join(parts).encode("utf-8"))


def build_eip712_auth_headers(method: str, url: str, body: Any, wallet: AWPWallet) -> dict:
    """Build EIP-712 signed headers untuk Mine API."""
    cfg = _fetch_sig_config()
    chain_id         = int(cfg.get("chain_id", cfg.get("chainId", 8453)))
    domain_name      = cfg.get("domain_name", cfg.get("domainName", "Mine"))
    domain_version   = cfg.get("domain_version", cfg.get("domainVersion", "1"))
    verifying_contract = cfg.get("verifying_contract", cfg.get("verifyingContract", "0x0000000000000000000000000000000000000000"))
    content_type     = "application/json"
    signed_headers   = ("content-type",)

    now   = int(time.time())
    nonce = secrets.randbits(52)
    split = urlsplit(url)
    req_headers = {"content-type": content_type}

    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name",              "type": "string"},
                {"name": "version",           "type": "string"},
                {"name": "chainId",           "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "APIRequest": [
                {"name": "method",      "type": "string"},
                {"name": "host",        "type": "string"},
                {"name": "path",        "type": "string"},
                {"name": "queryHash",   "type": "bytes32"},
                {"name": "headersHash", "type": "bytes32"},
                {"name": "bodyHash",    "type": "bytes32"},
                {"name": "nonce",       "type": "uint256"},
                {"name": "issuedAt",    "type": "uint256"},
                {"name": "expiresAt",   "type": "uint256"},
            ],
        },
        "primaryType": "APIRequest",
        "domain": {
            "name":              domain_name,
            "version":           domain_version,
            "chainId":           chain_id,
            "verifyingContract": verifying_contract,
        },
        "message": {
            "method":      method.upper(),
            "host":        split.netloc,
            "path":        split.path or "/",
            "queryHash":   _hash_query(url),
            "headersHash": _hash_headers(req_headers, signed_headers),
            "bodyHash":    _hash_body(body, content_type),
            "nonce":       nonce,
            "issuedAt":    now,
            "expiresAt":   now + 300,
        },
    }

    sig = wallet.sign_typed_data(typed_data)
    return {
        "Content-Type":      content_type,
        "X-Signer":          wallet.address,
        "X-Signature":       sig if sig.startswith("0x") else f"0x{sig}",
        "X-Nonce":           str(nonce),
        "X-Issued-At":       str(now),
        "X-Expires-At":      str(now + 300),
        "X-Chain-Id":        str(chain_id),
        "X-Signed-Headers":  ",".join(signed_headers),
    }


class TLSAdapter(HTTPAdapter):
    """Force TLS 1.2+ untuk fix SSL EOF di beberapa VPS."""
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)


class MineSession(requests.Session):
    """requests.Session dengan EIP-712 auth untuk Mine API."""

    def __init__(self, wallet: AWPWallet):
        super().__init__()
        self.wallet = wallet
        self.headers.update({"Accept": "application/json", "User-Agent": "MineBot/1.0"})
        self.mount("https://", TLSAdapter())

    def request(self, method, url, **kwargs):
        body = kwargs.get("json")
        auth = build_eip712_auth_headers(method, url, body, self.wallet)
        if "headers" in kwargs:
            kwargs["headers"].update(auth)
        else:
            kwargs["headers"] = auth
        return super().request(method, url, **kwargs)


# ─────────────────────────────────────────────
#  STAGE 1 — CRAWL
# ─────────────────────────────────────────────

def crawl_url(url: str, timeout: int = 15) -> str:
    """Fetch raw HTML dari URL target."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; MineBot/1.0; "
            "+https://minework.net)"
        )
    }
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.text


# ─────────────────────────────────────────────
#  STAGE 2 — CLEAN
# ─────────────────────────────────────────────

# Tag yang dibuang saat cleaning
_REMOVE_TAGS = {
    "script", "style", "noscript", "iframe", "header", "footer",
    "nav", "aside", "form", "button", "svg", "img", "figure",
    "advertisement", "ads", "cookie",
}

def clean_html(raw_html: str) -> str:
    """
    Bersihkan HTML:
    - Hapus script, style, nav, ads, dll
    - Kembalikan plaintext yang bersih
    """
    soup = BeautifulSoup(raw_html, "lxml")

    # Hapus tag tidak berguna
    for tag in soup.find_all(_REMOVE_TAGS):
        tag.decompose()

    # Hapus elemen dengan class/id yang mengandung kata berikut
    noise_keywords = [
        "ad", "ads", "advertisement", "cookie", "popup",
        "modal", "banner", "sidebar", "social", "share",
        "comment", "subscribe", "newsletter",
    ]
    for elem in soup.find_all(True):
        attrs = " ".join(str(v) for v in elem.attrs.values() if isinstance(v, (str, list)))
        if any(kw in attrs.lower() for kw in noise_keywords):
            elem.decompose()

    # Ambil teks bersih
    text = soup.get_text(separator="\n")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  STAGE 3 — STRUCTURE
# ─────────────────────────────────────────────

def structure_data(cleaned_text: str, schema: dict) -> dict:
    """
    Ekstrak data sesuai skema DataSet dari teks bersih.

    Urutan prioritas backend (semua GRATIS):
      1. Groq  — set GROQ_API_KEY (daftar di console.groq.com, no CC)
      2. Ollama — install lokal, tanpa akun (ollama.com/download)
      3. Rule-based fallback — tanpa AI
    """
    groq_key = os.getenv("GROQ_API_KEY", "")
    if groq_key:
        log.info("    [AI] Menggunakan Groq (Llama 3)")
        return _structure_with_groq(cleaned_text, schema, groq_key)

    if _ollama_available():
        log.info("    [AI] Menggunakan Ollama (lokal)")
        return _structure_with_ollama(cleaned_text, schema)

    log.warning("    [AI] Tidak ada backend AI, pakai rule-based fallback.")
    return _structure_rule_based(cleaned_text, schema)


# ── GROQ (gratis, daftar di console.groq.com) ─────────────────────────────────

def _structure_with_groq(text: str, schema: dict, api_key: str) -> dict:
    """
    Groq free tier: ~14.400 request/hari, model Llama 3.
    Daftar gratis: https://console.groq.com  (tidak perlu kartu kredit)
    """
    fields = schema.get("fields", schema.get("properties", {}))
    prompt = (
        "Extract structured data from the text below following this JSON schema exactly.\n"
        "Return ONLY valid JSON, no explanation, no markdown backticks.\n\n"
        f"Schema fields:\n{json.dumps(fields, indent=2)}\n\n"
        f"Text:\n{text[:4000]}\n\n"
        "JSON output:"
    )

    resp = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "llama-3.1-8b-instant",   # model gratis, super cepat
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
            "temperature": 0.1,
        },
        timeout=30,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"].strip()
    return _parse_json_response(content)


# ── OLLAMA (100% lokal, tanpa akun, tanpa internet) ───────────────────────────

def _ollama_available() -> bool:
    """Cek apakah Ollama sedang jalan di localhost."""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _structure_with_ollama(text: str, schema: dict) -> dict:
    """
    Ollama jalan lokal — install di https://ollama.com/download
    Lalu pull model: ollama pull llama3.2
    Tidak perlu internet, tidak perlu akun, gratis selamanya.
    """
    fields = schema.get("fields", schema.get("properties", {}))
    prompt = (
        "Extract structured data from the text below following this JSON schema exactly.\n"
        "Return ONLY valid JSON, no explanation, no markdown backticks.\n\n"
        f"Schema fields:\n{json.dumps(fields, indent=2)}\n\n"
        f"Text:\n{text[:4000]}\n\n"
        "JSON output:"
    )

    # Cari model yang tersedia, pilih yang ada
    available_models = _get_ollama_models()
    preferred = ["llama3.2", "llama3.1", "llama3", "mistral", "gemma2"]
    model = next((m for m in preferred if any(m in am for am in available_models)), None)

    if not model:
        # Pakai model pertama yang ada, atau default
        model = available_models[0] if available_models else "llama3.2"
        log.info(f"    [Ollama] Model: {model}")

    resp = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"temperature": 0.1},
        },
        timeout=120,  # model lokal bisa lebih lambat
    )
    resp.raise_for_status()
    content = resp.json()["message"]["content"].strip()
    return _parse_json_response(content)


def _get_ollama_models() -> list[str]:
    """Ambil daftar model yang sudah ter-pull di Ollama."""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        models = r.json().get("models", [])
        return [m["name"] for m in models]
    except Exception:
        return []


# ── HELPER ────────────────────────────────────────────────────────────────────

def _parse_json_response(content: str) -> dict:
    """Parse JSON dari response LLM, bersihkan backtick jika ada."""
    if "```" in content:
        for part in content.split("```"):
            part = part.strip().lstrip("json").strip()
            try:
                return json.loads(part)
            except json.JSONDecodeError:
                continue
    return json.loads(content)


def _structure_rule_based(text: str, schema: dict) -> dict:
    """
    Fallback sederhana tanpa AI.
    Ekstraksi berbasis keyword — akurasi terbatas.
    """
    fields = schema.get("fields", schema.get("properties", {}))
    result = {}
    lines = text.splitlines()

    for field_name, field_def in fields.items():
        field_type = field_def.get("type", "string") if isinstance(field_def, dict) else "string"
        # Cari baris yang mengandung nama field
        for i, line in enumerate(lines):
            if field_name.lower().replace("_", " ") in line.lower():
                # Ambil nilai setelah ":" atau baris berikutnya
                if ":" in line:
                    val = line.split(":", 1)[1].strip()
                elif i + 1 < len(lines):
                    val = lines[i + 1].strip()
                else:
                    val = ""

                if field_type == "number":
                    try:
                        result[field_name] = float(val.replace(",", ""))
                    except ValueError:
                        result[field_name] = None
                elif field_type == "boolean":
                    result[field_name] = val.lower() in ("yes", "true", "1")
                else:
                    result[field_name] = val
                break
        else:
            result[field_name] = None

    return result


# ─────────────────────────────────────────────
#  MINE API CALLS
# ─────────────────────────────────────────────

class MineClient:
    def __init__(self, session: MineSession):
        self.s = session

    def get_datasets(self) -> list[dict]:
        """GET /api/core/v1/datasets"""
        r = self.s.get(f"{MINE_API}/api/core/v1/datasets", timeout=10)
        r.raise_for_status()
        body = r.json()
        data = body.get("data", body)
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict):
            items = data.get("items", [])
            return [d for d in items if isinstance(d, dict)]
        return []

    def submit_task(self, dataset_id: str, url: str, cleaned: str, structured: dict) -> dict:
        """POST /api/mining/v1/submissions"""
        r = self.s.post(
            f"{MINE_API}/api/mining/v1/submissions",
            json={
                "dataset_id": dataset_id,
                "entries": [
                    {
                        "url": url,
                        "cleaned_data": cleaned,
                        "structured_data": structured,
                    }
                ],
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def send_heartbeat(self) -> None:
        """POST /api/mining/v1/heartbeat"""
        try:
            self.s.post(
                f"{MINE_API}/api/mining/v1/heartbeat",
                json={"client": "mine-bot"},
                timeout=5,
            )
        except Exception:
            pass

    def get_my_stats(self) -> dict:
        """GET /api/mining/v1/miners/me/stats"""
        r = self.s.get(f"{MINE_API}/api/mining/v1/miners/me/stats", timeout=10)
        r.raise_for_status()
        body = r.json()
        return body.get("data", body)


# ─────────────────────────────────────────────
#  MAIN MINING LOOP
# ─────────────────────────────────────────────

class Miner:
    def __init__(self):
        self.wallet = AWPWallet(AGENT_ID)
        self.session: MineSession | None = None
        self.client: MineClient | None = None
        self.task_count = 0
        self.success_count = 0
        self.last_heartbeat = 0

    def setup(self):
        self.wallet.unlock(SESSION_DUR)
        self.session = MineSession(self.wallet)
        self.client  = MineClient(self.session)

    def heartbeat_if_needed(self):
        now = time.time()
        if now - self.last_heartbeat > HEARTBEAT_SEC:
            self.client.send_heartbeat()
            self.last_heartbeat = now

    def pick_dataset(self, datasets: list[dict]) -> dict | None:
        """Pilih DataSet dengan task tersedia (random dari aktif)."""
        import random
        active = [d for d in datasets if d.get("status") == "active"]
        if not active:
            return None
        return random.choice(active)

    def process_task(self, url: str, dataset_id: str, schema: dict) -> bool:
        """Jalankan pipeline 3 stage untuk 1 URL. Return True jika berhasil."""
        log.info(f"  URL — {url}")

        try:
            # Stage 1: Crawl
            raw_html = crawl_url(url)
            log.info(f"    Stage 1 ✓ ({len(raw_html):,} bytes)")

            # Stage 2: Clean
            cleaned = clean_html(raw_html)
            if len(cleaned) < 100:
                log.warning("    Stage 2 ✗ — konten terlalu pendek, skip")
                return False
            log.info(f"    Stage 2 ✓ ({len(cleaned):,} chars)")

            # Stage 3: Structure
            structured = structure_data(cleaned, schema)
            filled = sum(1 for v in structured.values() if v is not None)
            total  = len(structured)
            log.info(f"    Stage 3 ✓ ({filled}/{total} field terisi)")

            # Submit
            result = self.client.submit_task(dataset_id, url, cleaned, structured)
            data = result.get("data", result)
            log.info(f"    Submit  ✓ {data}")
            return True

        except requests.HTTPError as e:
            log.error(f"    HTTP error {e.response.status_code}: {e.response.text[:200]}")
        except Exception as e:
            log.error(f"    Error: {e}")
        return False

    def run_epoch(self):
        """Jalankan satu epoch mining sampai target atau waktu habis."""
        import random

        log.info("=" * 55)
        log.info(f"  MULAI EPOCH — target {MIN_TASKS}+ submission")
        log.info("=" * 55)

        datasets = self.client.get_datasets()
        if not datasets:
            log.error("Tidak ada DataSet aktif!")
            return

        # Filter active only
        active_datasets = [d for d in datasets if d.get("status") in ("active", None)]
        if not active_datasets:
            active_datasets = datasets  # fallback jika status tidak ada

        log.info(f"DataSet tersedia: {len(active_datasets)}")
        for ds in active_datasets:
            log.info(f"  • {ds.get('name', ds.get('id'))} — {ds.get('description', '')[:60]}")

        while self.task_count < MAX_TASKS:
            self.heartbeat_if_needed()

            dataset = random.choice(active_datasets)
            schema    = dataset.get("schema", {})
            ds_name   = dataset.get("name", dataset.get("id"))
            ds_id     = dataset.get("id", "")

            # Ambil URL dari source_domains dataset
            source_domains = dataset.get("source_domains") or dataset.get("sourceDomains") or []
            if not source_domains:
                log.warning(f"  Dataset {ds_name} tidak punya source_domains, skip")
                time.sleep(5)
                continue

            # Pilih domain acak dan buat URL seed
            domain = random.choice(source_domains)
            if not domain.startswith("http"):
                domain = f"https://{domain}"
            url = domain

            log.info(f"\n[{self.task_count + 1}/{MAX_TASKS}] Dataset: {ds_name} | URL: {url}")
            ok = self.process_task(url, ds_id, schema)
            self.task_count  += 1
            if ok:
                self.success_count += 1

            time.sleep(SUBMIT_DELAY)

        log.info("\n" + "=" * 55)
        log.info(f"  EPOCH SELESAI")
        log.info(f"  Total task  : {self.task_count}")
        log.info(f"  Berhasil    : {self.success_count}")
        log.info(f"  Gagal       : {self.task_count - self.success_count}")
        rate = self.success_count / max(self.task_count, 1) * 100
        log.info(f"  Success rate: {rate:.1f}%")
        if self.task_count >= MIN_TASKS:
            log.info("  ✅ Memenuhi syarat reward epoch!")
        else:
            log.warning(f"  ⚠️  Kurang dari {MIN_TASKS} task — tidak dapat reward!")
        log.info("=" * 55)

    def show_stats(self):
        try:
            stats = self.client.get_my_stats()
            log.info("\n📊 Stats kamu di Mine:")
            log.info(f"  Credit score : {stats.get('credit_score', stats.get('creditScore', 'N/A'))}")
            log.info(f"  Tier         : {stats.get('tier', 'N/A')}")
            log.info(f"  Total tasks  : {stats.get('total_tasks', stats.get('totalTasks', 'N/A'))}")
            log.info(f"  Avg score    : {stats.get('avg_score', stats.get('avgScore', 'N/A'))}")
            log.info(f"  Total reward : {stats.get('total_rewards', stats.get('totalReward', 'N/A'))} $aMine")
        except Exception as e:
            log.warning(f"Tidak bisa fetch stats: {e}")

    def run(self):
        log.info("╔══════════════════════════════════════╗")
        log.info("║    Mine (minework.net) — Miner Bot   ║")
        log.info("╚══════════════════════════════════════╝")

        self.setup()
        self.show_stats()

        try:
            self.run_epoch()
            self.show_stats()
        except KeyboardInterrupt:
            log.info("\nDihentikan manual.")
        finally:
            self.wallet.lock()


# ─────────────────────────────────────────────
#  ENTRYPOINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    Miner().run()
