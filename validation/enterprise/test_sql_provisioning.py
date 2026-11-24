#!/usr/bin/env python3
"""Contract parity only; database refusal tests require real PostgreSQL."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


def statements(sql):
    sql = re.sub(r"--[^\n]*", "", sql)
    return [re.sub(r"\s+", " ", statement).strip().lower()
            for statement in sql.split(";") if statement.strip()]


class ProvisioningParity(unittest.TestCase):
    def test_manual_provisioning_matches_the_services_actual_schema(self):
        source = (ROOT / "aip-service/src/store/pg.rs").read_text()
        automatic = source.split('pub const SCHEMA: &str = r#"', 1)[1].split('"#;', 1)[0]
        manual = (ROOT / "deploy/sql/schema.sql").read_text()
        self.assertEqual(statements(manual), statements(automatic))


if __name__ == "__main__":
    unittest.main(verbosity=2)
