"""CloudGuard - multi-cloud configuration review, comparison and dashboarding.

Package layout:
  cloudsec/checks   - per-cloud check catalogs (pure logic over normalized snapshots)
  cloudsec/collectors - cloud SDK collectors producing normalized snapshots
  cloudsec/output   - HTML dashboard, CSV and JSON serializers
  cloudsec/*.py     - scanner, comparison engine, privilege validation, demo data
"""

__version__ = "1.0.0"
