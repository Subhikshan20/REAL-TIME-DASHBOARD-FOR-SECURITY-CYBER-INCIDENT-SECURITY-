"""
geo.py
======
Map GeoIP country *names* (as emitted by Wazuh/GeoLite2 ``country_name``) to
ISO 3166-1 alpha-3 codes for the choropleth.

Plotly is deprecating its built-in ``locationmode="country names"`` matcher, so
the dashboard supplies ISO-3 codes itself via ``locationmode="ISO-3"``. The
lookup is case-insensitive and tolerant of the common name variants GeoIP feeds
use (e.g. "USA", "Russian Federation", "South Korea"). Names with no mapping
return ``None`` and are simply omitted from the map (still shown in the caption).
"""

from __future__ import annotations

# Curated name -> ISO-3 table. Covers the realistic set of attacker-origin
# countries (and the offline sample's countries); extend as needed.
_COUNTRY_ISO3: dict[str, str] = {
    "afghanistan": "AFG",
    "albania": "ALB",
    "algeria": "DZA",
    "argentina": "ARG",
    "australia": "AUS",
    "austria": "AUT",
    "bangladesh": "BGD",
    "belarus": "BLR",
    "belgium": "BEL",
    "brazil": "BRA",
    "bulgaria": "BGR",
    "canada": "CAN",
    "chile": "CHL",
    "china": "CHN",
    "colombia": "COL",
    "croatia": "HRV",
    "czechia": "CZE",
    "czech republic": "CZE",
    "denmark": "DNK",
    "egypt": "EGY",
    "estonia": "EST",
    "finland": "FIN",
    "france": "FRA",
    "germany": "DEU",
    "greece": "GRC",
    "hong kong": "HKG",
    "hungary": "HUN",
    "india": "IND",
    "indonesia": "IDN",
    "iran": "IRN",
    "iraq": "IRQ",
    "ireland": "IRL",
    "israel": "ISR",
    "italy": "ITA",
    "japan": "JPN",
    "kazakhstan": "KAZ",
    "kenya": "KEN",
    "latvia": "LVA",
    "lithuania": "LTU",
    "luxembourg": "LUX",
    "malaysia": "MYS",
    "mexico": "MEX",
    "moldova": "MDA",
    "morocco": "MAR",
    "netherlands": "NLD",
    "new zealand": "NZL",
    "nigeria": "NGA",
    "north korea": "PRK",
    "norway": "NOR",
    "pakistan": "PAK",
    "philippines": "PHL",
    "poland": "POL",
    "portugal": "PRT",
    "romania": "ROU",
    "russia": "RUS",
    "saudi arabia": "SAU",
    "serbia": "SRB",
    "singapore": "SGP",
    "slovakia": "SVK",
    "slovenia": "SVN",
    "south africa": "ZAF",
    "south korea": "KOR",
    "spain": "ESP",
    "sweden": "SWE",
    "switzerland": "CHE",
    "taiwan": "TWN",
    "thailand": "THA",
    "turkey": "TUR",
    "ukraine": "UKR",
    "united arab emirates": "ARE",
    "united kingdom": "GBR",
    "united states": "USA",
    "vietnam": "VNM",
}

# Common variants/aliases that GeoIP feeds emit for the same country.
_ALIASES: dict[str, str] = {
    "usa": "united states",
    "u.s.": "united states",
    "u.s.a.": "united states",
    "united states of america": "united states",
    "uk": "united kingdom",
    "u.k.": "united kingdom",
    "great britain": "united kingdom",
    "russian federation": "russia",
    "korea, republic of": "south korea",
    "republic of korea": "south korea",
    "korea (south)": "south korea",
    "korea, democratic people's republic of": "north korea",
    "viet nam": "vietnam",
    "iran, islamic republic of": "iran",
    "the netherlands": "netherlands",
    "holland": "netherlands",
    "uae": "united arab emirates",
    "taiwan, province of china": "taiwan",
    "republic of china": "taiwan",
    "moldova, republic of": "moldova",
    "czech": "czechia",
}


def to_iso3(name: object) -> str | None:
    """Return the ISO 3166-1 alpha-3 code for a country name, or ``None``."""
    if name is None:
        return None
    key = str(name).strip().lower()
    if not key:
        return None
    key = _ALIASES.get(key, key)
    return _COUNTRY_ISO3.get(key)
