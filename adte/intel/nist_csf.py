"""NIST Cybersecurity Framework (CSF) 2.0 subcategories ADTE cites.

One source of truth for every CSF 2.0 ID and label ADTE emits: the technique
YAML's ``nist_detect`` / ``nist_category`` pair (enforced by
``tests/test_nist_csf.py``), the report's derived ``nist_phases``, the LLM
prompt's allowed list, and the ``csf_subcategories`` table that
``GET /api/mitre/map`` serves to the SPA.

Text is quoted verbatim from NIST CSWP 29, *The NIST Cybersecurity Framework
(CSF) 2.0* (February 2024), Appendix A.  Only the Detect subcategories ADTE
can honestly claim are listed:

- **DE.CM (Continuous Monitoring)** describes the monitoring that would
  surface a technique.  ADTE does not monitor anything itself — the SIEM
  does — so a DE.CM ID on a technique card means "the monitoring surface
  where this technique shows up", never "ADTE monitored this".
- **DE.AE (Adverse Event Analysis)** describes what ADTE actually does with
  an alert: analyse it, correlate it, enrich it with threat intelligence, and
  declare when it meets the incident criteria.

No RESPOND subcategory is listed: ADTE is recommend-only and never contains,
eradicates or recovers anything.

NIST 800-61 Phase: Detection & Analysis (SP 800-61 Rev. 3 maps this phase to
the CSF 2.0 DETECT Function).
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

# Continuous Monitoring (DE.CM): "Assets are monitored to find anomalies,
# indicators of compromise, and other potentially adverse events".  These are
# all five DE.CM subcategories in the CSF 2.0 core (Appendix A lists no -04,
# -05, -07 or -08).  The unpadded "DE.CM-1" .. "DE.CM-8" style is CSF 1.1;
# ADTE's YAML used it until 2026-10-01, including three IDs 2.0 lacks.
DE_CM: Mapping[str, str] = MappingProxyType({
    "DE.CM-01": "Networks and network services are monitored to find potentially adverse events",
    "DE.CM-02": "The physical environment is monitored to find potentially adverse events",
    "DE.CM-03": (
        "Personnel activity and technology usage are monitored to find potentially "
        "adverse events"
    ),
    "DE.CM-06": (
        "External service provider activities and services are monitored to find "
        "potentially adverse events"
    ),
    "DE.CM-09": (
        "Computing hardware and software, runtime environments, and their data are "
        "monitored to find potentially adverse events"
    ),
})

# Adverse Event Analysis (DE.AE): "Anomalies, indicators of compromise, and
# other potentially adverse events are analyzed to characterize the events and
# detect cybersecurity incidents".  Only the four ADTE performs.
DE_AE: Mapping[str, str] = MappingProxyType({
    "DE.AE-02": "Potentially adverse events are analyzed to better understand associated activities",
    "DE.AE-03": "Information is correlated from multiple sources",
    "DE.AE-07": (
        "Cyber threat intelligence and other contextual information are integrated "
        "into the analysis"
    ),
    "DE.AE-08": "Incidents are declared when adverse events meet the defined incident criteria",
})

# Every ID ADTE may emit, DE.CM first, in ID order.
CSF_SUBCATEGORIES: Mapping[str, str] = MappingProxyType({**DE_CM, **DE_AE})


def csf_subcategory_table() -> dict[str, str]:
    """Return a fresh, JSON-serializable copy of every CSF ID ADTE cites.

    Returns:
        ``{subcategory_id: official CSF 2.0 text}`` in ID order, DE.CM before
        DE.AE.  A new dict per call, so a caller cannot mutate the table.
    """
    return dict(CSF_SUBCATEGORIES)
