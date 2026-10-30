import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def normalize_domain(identifier: str) -> str:
    value = (identifier or "").strip().rstrip(".")

    if not value:
        raise ValueError("Domain cannot be empty.")

    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid domain name.")

    if len(value) > 253:
        raise ValueError("Domain name is too long.")

    labels = value.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            raise ValueError("Invalid domain name.")

    return value


def normalize_ip(identifier: str) -> str:
    value = (identifier or "").strip()

    if not value:
        raise ValueError("IP address cannot be empty.")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("Invalid IP address.")


def normalize_url(identifier: str) -> str:
    value = (identifier or "").strip()

    if not value:
        raise ValueError("URL cannot be empty.")

    parsed = urlsplit(value)

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("A valid HTTP or HTTPS URL is required.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported.")

    try:
        host = parsed.hostname
        try:
            host = normalize_ip(host)
        except ValueError:
            host = normalize_domain(host)

        port = parsed.port
    except ValueError as error:
        raise ValueError("Invalid URL host or port.") from error

    if ":" in host:
        host = f"[{host}]"

    netloc = host
    if port:
        netloc = f"{netloc}:{port}"

    return urlunsplit((
        parsed.scheme.lower(),
        netloc,
        parsed.path or "/",
        parsed.query,
        parsed.fragment
    ))


def normalize_indicator(entity_type: str, identifier: str) -> str:
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
