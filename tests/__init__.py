from __future__ import unicode_literals
import unittest
from . import test_miracl_api_tornado


def test_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_miracl_api_tornado)
    return suite
