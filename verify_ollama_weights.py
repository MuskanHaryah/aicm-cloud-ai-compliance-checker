"""MDS-08 on the LOCAL model host: re-hash the real Gemma weights file that Ollama stores and
compare it with the digest recorded in Ollama's own manifest.

Ollama stores model files content-addressed: blobs/sha256-<hex>, where <hex> is the SHA-256 of
the file. If the file is modified (or corrupted) the recalculated hash no longer equals <hex>.
NOTE: the "digest" shown by `ollama list` / /api/tags is the digest of the MANIFEST, not of the
weights, so it must not be used as the model checksum.

Usage:  python verify_ollama_weights.py [model]      (default gemma3n:e4b)
Env:    OLLAMA_MODELS  if the models are not in ~/.ollama/models
Exit code: 0 = OK, 1 = tampered/corrupt, 2 = not found.
Re-hashing a ~7 GB file takes about a minute."""
import hashlib
import json
import os
import sys

CHUNK = 8 * 1024 * 1024


def models_root():
    return os.environ.get("OLLAMA_MODELS") or os.path.join(os.path.expanduser("~"), ".ollama", "models")


def verify(model="gemma3n:e4b"):
    """Returns (status, detail) with status in OK / TAMPERED / NOT-FOUND."""
    root = models_root()
    name, _, tag = model.partition(":")
    manifest = os.path.join(root, "manifests", "registry.ollama.ai", "library", name, tag or "latest")
    if not os.path.isfile(manifest):
        return "NOT-FOUND", f"manifest not found: {manifest} (set OLLAMA_MODELS if the models are elsewhere)"
    layers = json.load(open(manifest, encoding="utf-8")).get("layers", [])
    weights = [l for l in layers if l.get("mediaType") == "application/vnd.ollama.image.model"]
    if not weights:
        return "NOT-FOUND", "manifest has no model-weights layer"
    expected = weights[0]["digest"].split(":", 1)[1]
    blob = os.path.join(root, "blobs", "sha256-" + expected)
    if not os.path.isfile(blob):
        return "NOT-FOUND", f"weights file missing: {blob}"
    h = hashlib.sha256()
    with open(blob, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    actual = h.hexdigest()
    if actual == expected:
        return "OK", f"recalculated SHA-256 equals the manifest digest ({expected[:12]}...)"
    return "TAMPERED", f"recalculated {actual[:12]}... != manifest digest {expected[:12]}..."


if __name__ == "__main__":
    status, detail = verify(sys.argv[1] if len(sys.argv) > 1 else "gemma3n:e4b")
    print(f"MDS-08 local weights check: {status}: {detail}")
    sys.exit({"OK": 0, "TAMPERED": 1}.get(status, 2))
