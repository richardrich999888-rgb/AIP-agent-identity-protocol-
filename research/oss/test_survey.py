"""Unit tests for survey.py's pure functions (no network)."""

import unittest

import survey as s


class Classify(unittest.TestCase):
    def test_apache_across_line_breaks(self):
        self.assertEqual(s.classify("  Apache License\n   Version 2.0, January 2004"), "Apache-2.0")

    def test_mit(self):
        self.assertEqual(s.classify("MIT\n\nPermission is hereby granted, free of charge, to any"), "MIT")

    def test_elastic_beats_apache_mention(self):
        # ELv2 texts can mention other licenses; the stronger signature is first.
        self.assertEqual(s.classify("Elastic License 2.0 ... Apache License Version 2.0"), "Elastic-2.0")

    def test_agpl_not_read_as_gpl(self):
        self.assertEqual(s.classify("GNU AFFERO GENERAL PUBLIC LICENSE"), "AGPL")

    def test_custom_text_is_unrecognised(self):
        self.assertEqual(s.classify("The Example Enterprise license (the License)"), "UNRECOGNISED")

    def test_empty(self):
        self.assertEqual(s.classify(""), "UNRECOGNISED")


LS = "aaa\tHEAD\nbbb\trefs/tags/v1\nccc\trefs/tags/v2\nddd\trefs/tags/v2^{}\n"


class Resolve(unittest.TestCase):
    def test_lightweight_tag(self):
        self.assertEqual(s.resolve(LS, "v1"), "bbb")

    def test_annotated_tag_is_peeled(self):
        self.assertEqual(s.resolve(LS, "v2"), "ddd")

    def test_head(self):
        self.assertEqual(s.resolve(LS, None), "aaa")

    def test_missing_tag_raises(self):
        with self.assertRaises(LookupError):
            s.resolve(LS, "v3")

    def test_missing_head_raises(self):
        with self.assertRaises(LookupError):
            s.resolve("bbb\trefs/tags/v1\n", None)

    def test_prefix_tag_does_not_match(self):
        with self.assertRaises(LookupError):
            s.resolve(LS, "v")


class Paths(unittest.TestCase):
    P = [
        "LICENSE", "enterprise/LICENSE.md", "a/b/c/LICENSE", "a/b/c/d/LICENSE",
        "vendor/x/LICENSE", "web/node_modules/y/LICENSE", "NOTICE", "src/license.go",
        "ee/server/x.go", "web/src/ee/y.ts", "deep/a/b/ee/z.ts", "README.md",
    ]

    def test_license_paths(self):
        self.assertEqual(
            s.license_paths(self.P),
            ["LICENSE", "NOTICE", "a/b/c/LICENSE", "enterprise/LICENSE.md", "src/license.go"],
        )

    def test_enterprise_dirs(self):
        self.assertEqual(s.enterprise_dirs(self.P), ["ee", "enterprise", "web/src/ee"])

    def test_extensions_deterministic(self):
        self.assertEqual(s.extensions(["a.go", "b.go", "c.ts", "d.py", "Makefile"])[0], (".go", 2))
        self.assertEqual(s.extensions(["b.ts", "a.py"]), [(".py", 1), (".ts", 1)])


if __name__ == "__main__":
    unittest.main()
