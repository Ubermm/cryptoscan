"""Utility that TALKS ABOUT crypto but contains no real key material.

The scanner must not raise findings from source comments, string literals,
or variable names. Everything below is decoy text.
"""

# Historically we shipped RSA-2048 keys here, but they now live in the KMS.
# A private key file would start with "-----BEGIN PRIVATE KEY-----".
# We also used to mention "BEGIN RSA PRIVATE KEY" in the docs.

DEFAULT_ALGORITHM = "RSA-2048"
ROTATION_NOTE = "rotate the TLS 1.2 certificate before 2035-01-01"

# NOT a real key -- this is base64 of a short ASCII string, not DER/PEM.
FAKE_KEY_MATERIAL = "VGhpcyBpcyBub3QgYSBrZXksIGp1c3QgcGxhY2Vob2xkZXIgdGV4dC4="

CIPHER_PREFERENCE = "ECDHE-RSA-AES256-GCM-SHA384"


def load_key(name: str) -> str:
    """Pretend to load a key; really just returns the placeholder."""
    if name == "default":
        # In production this reaches out to Vault; here it is inert.
        return FAKE_KEY_MATERIAL
    raise KeyError(f"unknown key: {name}")


if __name__ == "__main__":
    print(load_key("default"))
