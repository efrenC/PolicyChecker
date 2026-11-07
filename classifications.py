"""The security classification scheme.

This is the single source of truth for which levels exist and how they rank.
To change the scheme, edit SecurityLevel below: members are listed from
lowest to highest risk, and everything else derives from that order.
"""

from enum import Enum


class SecurityLevel(str, Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


# Level name -> risk rank (1 = lowest), derived from the order above.
SECURITY_ORDER: dict[str, int] = {
    level.value: rank for rank, level in enumerate(SecurityLevel, start=1)
}

VALID_CLASSES = set(SECURITY_ORDER)
