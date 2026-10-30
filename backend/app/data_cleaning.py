import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def normalize_domain(identifier: str) -> str:
    value = (identifier or "").strip().rstrip(".")

    if not value:
        raise ValueError("Domain cannot be empty.")

    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid domain name.") from error

    if len(value) > 253:
        raise ValueError("Domain name is too long.")

    labels = value.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        ):
            raise ValueError("Invalid domain name.")

    return value


def normalize_ip(identifier: str) -> str:
    value = (identifier or "").strip()

    if not value:
        raise ValueError("IP address cannot be empty.")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError("Invalid IP address.") from error


def normalize_url(identifier: str) -> str:
    value = (identifier or "").strip()

    if not value:
        raise ValueError("URL cannot be empty.")

    try:
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname:
            raise ValueError("URL must contain a hostname.")

        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are not supported.")

        host = parsed.hostname

        try:
            host = normalize_ip(host)
        except ValueError:
            host = normalize_domain(host)

        port = parsed.port

        if ":" in host:
            host = f"[{host}]"

        netloc = host

        if port and not (
            (parsed.scheme.lower() == "http" and port == 80)
            or (parsed.scheme.lower() == "https" and port == 443)
        ):
            netloc = f"{host}:{port}"

        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            parsed.fragment
        ))

    except ValueError as error:
        raise ValueError("Invalid URL, hostname, or port.") from error


def normalize_indicator(entity_type: str, identifier: str) -> str:
    entity_type = (entity_type or "").strip().lower()

    if entity_type == "domain":
        return normalize_domain(identifier)

    if entity_type == "ip":
        return normalize_ip(identifier)

    if entity_type in {"malware", "threat_actor"}:
        value = (identifier or "").strip()

        if not value:
            raise ValueError("Indicator name cannot be empty.")

        return value

    raise ValueError("Unsupported entity type.")
