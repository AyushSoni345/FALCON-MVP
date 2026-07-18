import ipaddress
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from app.core.enrichment.base import BaseEnricher
from app.logging_config import log_pipeline

GEO_DATABASE = {
    "185.220.101.5": {
        "country": "Germany",
        "region": "Berlin",
        "city": "Berlin",
        "asn": "AS20473",
        "isp": "Tor Server Provider",
        "latitude": 52.5200,
        "longitude": 13.4050,
        "risk_score": 9.0
    },
    "45.9.148.15": {
        "country": "Russia",
        "region": "Moscow",
        "city": "Moscow",
        "asn": "AS60924",
        "isp": "ShadowNet Hosting",
        "latitude": 55.7558,
        "longitude": 37.6173,
        "risk_score": 10.0
    },
    "8.8.8.8": {
        "country": "United States",
        "region": "California",
        "city": "Mountain View",
        "asn": "AS15169",
        "isp": "Google LLC",
        "latitude": 37.4220,
        "longitude": -122.0841,
        "risk_score": 0.0
    },
    "106.51.78.23": {
        "country": "India",
        "region": "Karnataka",
        "city": "Bengaluru",
        "asn": "AS9829",
        "isp": "BSNL",
        "latitude": 12.9716,
        "longitude": 77.5946,
        "risk_score": 0.0
    }
}

class GeoService(BaseEnricher):
    """Enriches event contexts with geographic and network routing information."""

    def is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return True

    def get_deterministic_geo(self, ip_str: str) -> Dict[str, Any]:
        hash_val = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
        
        countries = [
            ("United States", "New York", "New York", "AS701", "Verizon Business", 40.7128, -74.0060, 1.0),
            ("India", "Maharashtra", "Mumbai", "AS55836", "Reliance Jio Infocomm", 19.0760, 72.8777, 0.0),
            ("United Kingdom", "England", "London", "AS12576", "EE Limited", 51.5074, -0.1278, 1.0),
            ("Singapore", "Central", "Singapore", "AS4657", "StarHub Mobile", 1.3521, 103.8198, 0.0),
            ("China", "Beijing", "Beijing", "AS4134", "Chinanet", 39.9042, 116.4074, 4.0),
        ]
        
        selected = countries[hash_val % len(countries)]
        return {
            "country": selected[0],
            "region": selected[1],
            "city": selected[2],
            "asn": selected[3],
            "isp": selected[4],
            "latitude": selected[5],
            "longitude": selected[6],
            "risk_score": selected[7]
        }

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        geo = event.get("geo_context", {})
        net = event.get("network_context", {})
        ident = event.get("identity_context", {})
        info = event.get("event_information", {})

        event_uuid = info.get("event_uuid")
        corr_id = info.get("correlation_id")

        log_pipeline(
            logging.DEBUG,
            "Initiating geographic context enrichment.",
            "geo_enrichment",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        ip_address = net.get("public_ip") or net.get("source_ip") or ident.get("ip_address")
        
        now_str = datetime.utcnow().replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        geo_source = "IP_Lookup"

        gps_lat = geo.get("latitude")
        gps_lon = geo.get("longitude")

        if gps_lat is not None and gps_lon is not None and gps_lat != 0.0 and gps_lon != 0.0:
            country = geo.get("country") or net.get("country") or "India"
            city = geo.get("city") or net.get("city") or "Mumbai"
            region = geo.get("region") or "Maharashtra"
            geo_source = geo.get("geo_source") or "GPS"
        elif not ip_address:
            country, city, region, lat, lon = "Internal Network", "Private subnet", "Local", 0.0, 0.0
            asn, isp = "N/A", "Internal Routing"
            gps_lat, gps_lon = lat, lon
            geo_source = "Localhost"
        elif self.is_private_ip(ip_address):
            country, city, region, lat, lon = "Internal Network", "Private subnet", "Local", 0.0, 0.0
            asn, isp = "N/A", "Internal Routing"
            gps_lat, gps_lon = lat, lon
            geo_source = "PrivateIP"
        else:
            if ip_address in GEO_DATABASE:
                db_info = GEO_DATABASE[ip_address]
            else:
                db_info = self.get_deterministic_geo(ip_address)
            
            country = db_info["country"]
            city = db_info["city"]
            region = db_info["region"]
            gps_lat = db_info["latitude"]
            gps_lon = db_info["longitude"]
            asn = db_info["asn"]
            isp = db_info["isp"]
            geo_source = "IP_Database"

        geo.update({
            "country": country,
            "city": city,
            "region": region,
            "latitude": gps_lat,
            "longitude": gps_lon,
            "timezone": "UTC",
            "asn": geo.get("asn") or (asn if 'asn' in locals() else "N/A"),
            "isp": geo.get("isp") or (isp if 'isp' in locals() else "Internal Routing"),
            "geo_source": geo_source,
            "lookup_timestamp": now_str
        })

        event["geo_context"] = geo

        if "asn" in locals() and asn != "N/A":
            net["asn"] = asn
        if "isp" in locals() and isp != "Internal Routing":
            net["isp"] = isp
        if country != "Internal Network":
            net["country"] = country
            net["city"] = city

        log_pipeline(
            logging.DEBUG,
            f"Geographic lookup resolved: Country={country}, City={city}, Source={geo_source}",
            "geo_enrichment",
            "success",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        return event
