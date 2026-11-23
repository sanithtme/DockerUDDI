"""Create/verify/destroy test DNS zones and the DHCP network in Universal DDI."""
from .client import DdiApiError, DdiClient
from .ipam import IpamApplyResult, IpamManager, parse_ipam_specs
from .manager import ApplyResult, RecordSpec, VerifyRow, ZoneManager, ZoneSpec, parse_zone_specs

__all__ = ["ApplyResult", "DdiApiError", "DdiClient", "IpamApplyResult", "IpamManager", "RecordSpec",
           "VerifyRow", "ZoneManager", "ZoneSpec", "parse_ipam_specs", "parse_zone_specs"]
