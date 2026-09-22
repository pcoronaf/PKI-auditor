"""Clasificacion de dominios y de terceros.

FirmaScope necesita responder "que terceros recibieron trafico despues del
acceso a las credenciales". Para ello calcula el dominio registrable de cada
peticion con una lista de sufijos publicos reducida (suficiente para los
dominios habituales en Mexico y para los TLD genericos) y la compara con el
dominio del objetivo.
"""

from __future__ import annotations

from urllib.parse import urlsplit

#: Sufijos de segundo nivel frecuentes: ``example.com.mx`` -> ``example.com.mx``.
SECOND_LEVEL = frozenset(
    {
        "com", "org", "net", "edu", "gob", "gov", "mil", "int", "ac", "co",
        "ne", "or", "gen", "nom", "info", "web", "biz",
    }
)

#: ccTLD de dos letras donde SECOND_LEVEL aplica (``.com.mx``, ``.co.uk``...).
CCTLD_LENGTH = 2

#: Sufijos multi-etiqueta que no siguen la regla anterior.
EXPLICIT_SUFFIXES = frozenset(
    {
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app",
        "netlify.app", "azurewebsites.net", "cloudfront.net", "amazonaws.com",
        "firebaseapp.com", "web.app", "herokuapp.com", "blob.core.windows.net",
    }
)

#: Terceros conocidos, para etiquetar el reporte de forma legible.
KNOWN_THIRD_PARTIES = {
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "analytics.google.com": "Google Analytics",
    "doubleclick.net": "Google Ads",
    "googleapis.com": "Google APIs",
    "gstatic.com": "Google Static",
    "cloudflare.com": "Cloudflare",
    "cloudflareinsights.com": "Cloudflare Insights",
    "cdnjs.cloudflare.com": "Cloudflare CDN",
    "jsdelivr.net": "jsDelivr CDN",
    "unpkg.com": "unpkg CDN",
    "sentry.io": "Sentry",
    "ingest.sentry.io": "Sentry",
    "bugsnag.com": "Bugsnag",
    "newrelic.com": "New Relic",
    "nr-data.net": "New Relic",
    "datadoghq.com": "Datadog",
    "hotjar.com": "Hotjar",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "facebook.net": "Meta Pixel",
    "facebook.com": "Meta",
    "clarity.ms": "Microsoft Clarity",
    "bing.com": "Microsoft Bing",
    "hubspot.com": "HubSpot",
    "intercom.io": "Intercom",
    "recaptcha.net": "reCAPTCHA",
    "jquery.com": "jQuery CDN",
    "bootstrapcdn.com": "Bootstrap CDN",
    "fontawesome.com": "Font Awesome",
    "typekit.net": "Adobe Fonts",
}

#: Categorias de tercero relevantes para el modelo de amenazas.
TELEMETRY_KEYWORDS = (
    "analytics", "telemetry", "metrics", "tracking", "tracker", "beacon",
    "collect", "stats", "logs", "sentry", "bugsnag", "datadog", "newrelic",
    "clarity", "hotjar", "mixpanel", "amplitude", "segment", "pixel",
)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def registrable_domain(host_or_url: str) -> str:
    """Devuelve el dominio registrable (eTLD+1) de forma heuristica."""
    host = host_or_url
    if "://" in host_or_url:
        host = host_of(host_or_url)
    host = (host or "").strip(".").lower()
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return host  # direccion IP o host sin puntos
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    for suffix in EXPLICIT_SUFFIXES:
        if host.endswith("." + suffix):
            extra = suffix.count(".") + 2
            return ".".join(labels[-extra:])
    tld = labels[-1]
    sld = labels[-2]
    if len(tld) == CCTLD_LENGTH and sld in SECOND_LEVEL and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_third_party(url: str, target: str, extra_first_party: list[str] | None = None) -> bool:
    """True si ``url`` pertenece a un dominio registrable distinto al objetivo."""
    host = host_of(url)
    if not host:
        return False
    domain = registrable_domain(host)
    target_domain = registrable_domain(target)
    if not target_domain:
        return False
    if domain == target_domain:
        return False
    for allowed in extra_first_party or []:
        if domain == registrable_domain(allowed):
            return False
    return True


def third_party_name(url_or_host: str) -> str:
    """Nombre legible del tercero, si se reconoce."""
    host = host_of(url_or_host) if "://" in url_or_host else url_or_host.lower()
    if not host:
        return ""
    for suffix, name in KNOWN_THIRD_PARTIES.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return ""


def looks_like_telemetry(url: str) -> bool:
    """Heuristica de endpoint de telemetria (host o ruta)."""
    lowered = url.lower()
    return any(keyword in lowered for keyword in TELEMETRY_KEYWORDS)


def is_local(url: str) -> bool:
    host = host_of(url)
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")
