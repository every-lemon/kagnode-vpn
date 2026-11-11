"""Source-only stable tags cannot be mistaken for signed native updates."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import vpn_release


def native(tag, *, prerelease=False, draft=False):
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "assets": [
            {"name": name} for name in ("manifest.json", "manifest.sig", "update.sh")
        ],
    }


class NativeReleaseSelectionTests(unittest.TestCase):
    def test_newer_source_only_tag_does_not_hide_native_candidate(self):
        old = native("v4.1.0")
        source = {"tag_name": "v5.0.0", "assets": [{"name": "release-manifest.json"}]}
        self.assertIs(vpn_release.select([old, source]), old)

    def test_prerelease_policy_and_draft_exclusion_remain(self):
        old = native("v4.1.0")
        beta = native("v4.2.0-beta.1", prerelease=True)
        draft = native("v6.0.0", draft=True)
        self.assertIs(vpn_release.select([draft, beta, old]), old)
        self.assertIs(vpn_release.select([draft, beta, old], True), beta)

    def test_incomplete_or_malformed_native_assets_are_not_candidates(self):
        for assets in (
            None,
            {},
            [None],
            [{"name": "manifest.json"}, {"name": "update.sh"}],
        ):
            with (
                self.subTest(assets=assets),
                self.assertRaisesRegex(ValueError, "signed native"),
            ):
                vpn_release.select([{"tag_name": "v5.0.0", "assets": assets}])


if __name__ == "__main__":
    unittest.main()
