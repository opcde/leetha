"""Run data-integrity checks and produce validation reports.

Provides the async entry point for the 'validate' subcommand, which
can execute individual checks or a full validation suite and persist
the resulting report to disk.
"""

from __future__ import annotations

import json

from leetha.config import get_config
from leetha.store.database import Database
from leetha.analysis.validator import (
    run_validation,
    validate_oui_coverage,
    validate_manufacturer_consistency,
    validate_stale_devices,
)


_CHECK_DISPATCH = {
    "oui": lambda db, cache: validate_oui_coverage(db, cache),
    "manufacturer": lambda db, cache: validate_manufacturer_consistency(db, cache),
    "stale": lambda db, _cache: validate_stale_devices(db),
}


async def handle_validation(parsed_args):
    """Execute one or all data-validation checks and display results.

    When a specific --check is given, only that single validator runs.
    Otherwise the full suite executes and the report is saved to disk.
    """
    cfg = get_config()
    storage = Database(cfg.db_path)
    await storage.initialize()

    # The validator reads hosts/verdicts, which are owned by Store -- not by
    # Database's own schema. On a database that has never seen a capture run
    # those tables don't exist yet, and every check dies with a raw
    # "no such table: hosts" traceback.
    from leetha.store.store import Store
    _schema = Store(cfg.db_path)
    await _schema.initialize()
    await _schema.close()

    try:
        target_check = parsed_args.check
        detailed = parsed_args.verbose

        if target_check:
            dispatcher = _CHECK_DISPATCH[target_check]
            outcome = await dispatcher(storage, cfg.cache_dir)

            if detailed:
                print(json.dumps(outcome, indent=2))
            else:
                if "count" in outcome:
                    print(f"Stale devices: {outcome['count']}")
                else:
                    print(f"Passed: {outcome['passed']}, Failed: {outcome['failed']}")
        else:
            full_report = await run_validation(storage, cfg.cache_dir)

            if detailed:
                print(json.dumps(full_report, indent=2))
            else:
                print(f"Validation Report ({full_report['timestamp']})")
                for label, check_data in full_report["checks"].items():
                    if "count" in check_data:
                        print(f"  {label}: {check_data['count']} issues")
                    else:
                        verdict = "PASS" if check_data["failed"] == 0 else "FAIL"
                        print(
                            f"  {label}: {verdict} "
                            f"({check_data['passed']} passed, "
                            f"{check_data['failed']} failed)"
                        )

            output_path = cfg.data_dir / "validation_report.json"
            with open(output_path, "w") as fh:
                json.dump(full_report, fh, indent=2)
            print(f"\nReport saved to {output_path}")
    finally:
        await storage.close()


# Backward-compatible alias
run_validate = handle_validation
