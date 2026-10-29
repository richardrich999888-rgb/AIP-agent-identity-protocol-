"""Portable publication safety fixtures; never genuine model execution evidence."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from evidence import Refused
from hosted_agent_zero import publish_self_reported_file


class HostedPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.work=self.root/'work'; self.work.mkdir()
        self.public=self.root/'public'; self.public.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_original_noncanonical_bytes_and_source_standing_are_preserved(self):
        original=b'{ "source" : "ordinary unit fixture" }\n\n'
        (self.work/'response.json').write_bytes(original)
        result=publish_self_reported_file(self.work,self.public,'response.json',1024)
        self.assertEqual((self.public/result['published_file']).read_bytes(),original)
        self.assertEqual(result['sha256'],hashlib.sha256(original).hexdigest())
        self.assertEqual(result['source_authority'],'AGENT_SELF_REPORTED')
        self.assertIn('not independent',result['claim_standing'])

    def test_missing_diagnostic_is_explicit_and_creates_no_record(self):
        result=publish_self_reported_file(self.work,self.public,'response.json',1024)
        self.assertEqual(result['status'],'NOT_PRODUCED')
        self.assertEqual(list(self.public.iterdir()),[])

    def test_symlink_and_nonregular_files_are_refused_without_export(self):
        target=self.root/'fixture-secret'; target.write_text('unit fixture only')
        symlink=self.work/'response.json'; symlink.symlink_to(target)
        with self.assertRaises(Refused):
            publish_self_reported_file(self.work,self.public,'response.json',1024)
        symlink.unlink(); symlink.mkdir()
        with self.assertRaises(Refused):
            publish_self_reported_file(self.work,self.public,'response.json',1024)
        symlink.rmdir(); os.mkfifo(symlink)
        with self.assertRaises(Refused):
            publish_self_reported_file(self.work,self.public,'response.json',1024)
        self.assertEqual(list(self.public.iterdir()),[])

    def test_oversized_diagnostic_is_refused_without_truncating_or_exporting(self):
        original=b'x'*1025
        (self.work/'adapter.jsonl').write_bytes(original)
        with self.assertRaises(Refused):
            publish_self_reported_file(self.work,self.public,'adapter.jsonl',1024)
        self.assertEqual((self.work/'adapter.jsonl').read_bytes(),original)
        self.assertEqual(list(self.public.iterdir()),[])

    def test_path_escape_is_refused(self):
        with self.assertRaises(Refused):
            publish_self_reported_file(self.work,self.public,'../outside',1024)


if __name__=='__main__':
    unittest.main()
