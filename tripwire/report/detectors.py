"""Back-compat re-export. Output detection is a GATE control (the defended configuration's
disclosure half), so it now lives in `tripwire.gate.output_guard`. This module re-exports
`scan_output` so existing importers keep working; the runtime guard that actually withholds a
disclosing response is `tripwire.gate.output_guard.OutputGuard`.
"""

from __future__ import annotations

from tripwire.gate.output_guard import scan_output

__all__ = ["scan_output"]
