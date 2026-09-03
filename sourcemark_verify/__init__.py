"""sourcemark-verify — check a Sourcemark receipt offline.

    from sourcemark_verify import verify
    report = verify(receipt_bytes, log_key_pem, cited_text=text)
    report.outcome        # one of seven, or MALFORMED
    report.exit_status    # 0 / 1 / 2 / 3 / 4

Written from `spec/` alone. It shares no code with the emitter, because two
implementations that agree by calling the same function agree about nothing.

SPDX-License-Identifier: Apache-2.0
"""

from .verify import Check, MissingInput, Report, load_log_key, verify

__version__ = "0.1.0.dev0"
__all__ = ["verify", "Report", "Check", "MissingInput", "load_log_key", "__version__"]
