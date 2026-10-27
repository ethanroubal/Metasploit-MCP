import math
import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Config:
    url: str = "http://127.0.0.1:55553/api/"
    username: str = "msf"
    password: str = field(default="", repr=False)
    token: str = field(default="", repr=False)
    timeout: float = 30.0
    verify_tls: bool = True
    ca_file: str = ""
    max_response_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        parsed = urlsplit(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MSF_RPC_URL must be an http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Put RPC credentials in environment variables, not the URL")
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("This local bridge requires a loopback RPC URL")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("MSF_RPC_TIMEOUT must be a positive finite number")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if not self.verify_tls and parsed.scheme != "https":
            raise ValueError("MSF_RPC_VERIFY_TLS=false only applies to HTTPS")
        if self.ca_file and not self.verify_tls:
            raise ValueError("A CA file cannot be combined with disabled TLS verification")

    @classmethod
    def from_env(cls):
        verify = os.getenv("MSF_RPC_VERIFY_TLS", "true").lower()
        if verify not in {"true", "false"}:
            raise ValueError("MSF_RPC_VERIFY_TLS must be true or false")
        return cls(
            url=os.getenv("MSF_RPC_URL", "http://127.0.0.1:55553/api/"),
            username=os.getenv("MSF_RPC_USER", "msf"),
            password=os.getenv("MSF_RPC_PASS", ""),
            token=os.getenv("MSF_RPC_TOKEN", ""),
            timeout=float(os.getenv("MSF_RPC_TIMEOUT", "30")),
            verify_tls=verify == "true",
            ca_file=os.getenv("MSF_RPC_CA_FILE", ""),
            max_response_bytes=int(os.getenv("MSF_RPC_MAX_RESPONSE_BYTES", "67108864")),
        )
