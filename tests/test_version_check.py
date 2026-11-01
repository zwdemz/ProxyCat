"""Regression coverage for the upstream V3.0.1 release metadata parser."""

import json
import unittest

from modules.version_check import _extract_versions, _latest_of, _not_newer


class VersionMetadataTests(unittest.TestCase):
    def test_json_uses_release_tags_instead_of_versions_in_the_body(self):
        metadata = json.dumps([{'tag_name': 'ProxyCat-V3.0.1',
                                'body': 'Future plan ProxyCat-V9.0.0'}])
        self.assertEqual(['ProxyCat-V3.0.1'], _extract_versions(metadata))

    def test_atom_selects_latest_release_numerically(self):
        atom = ('<feed xmlns="http://www.w3.org/2005/Atom">'
                '<entry><title>ProxyCat-V3.0.1</title></entry>'
                '<entry><title>ProxyCat-V2.9.9</title></entry></feed>')
        self.assertEqual('ProxyCat-V3.0.1', _latest_of(_extract_versions(atom)))

    def test_current_release_is_not_reported_as_an_update(self):
        self.assertTrue(_not_newer('ProxyCat-V3.0.1', 'ProxyCat-V3.0.1'))
        self.assertFalse(_not_newer('ProxyCat-V3.1.0', 'ProxyCat-V3.0.1'))
