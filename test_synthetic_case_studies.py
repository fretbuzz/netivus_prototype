import unittest
import io
import sys
import main, flowchart_algo
from unittest import mock

class TestStringMethods(unittest.TestCase):

    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())

    def test_split(self):
        s = 'hello world'
        self.assertEqual(s.split(), ['hello', 'world'])
        # check that s.split fails when the separator is not a string
        with self.assertRaises(TypeError):
            s.split(2)


class Test_Base_Network_Works(unittest.TestCase):
    def test_base_network(self):
        pass

class Test_Allowed_But_Should_Be_Blocked(unittest.TestCase):

    @mock.patch('module_under_test.input', create=True)
    def test_acl_shadowed(self):
        # output code from here: https://stackoverflow.com/questions/33767627/python-write-unittest-for-console-print
        # then input code can be @patch (for mock unittest) :: https://stackoverflow.com/questions/47690020/python-3-unit-tests-with-user-input
        flowchart_algo.side_effect = ['Albert Einstein', '42.81', 'done'] # each time the module calls for input, it'll take the next value from this list (i.e. reads left to right, one val per input request)

        capturedOutput = io.StringIO()  # Create StringIO object
        sys.stdout = capturedOutput

        # TODO: put the actual function call here
        pass

        sys.stdout = sys.__stdout__  # Reset redirect.
        print('Captured', capturedOutput.getvalue())  # print the output, so that we can see it

        # TODO: write the tests for the output here

    def test_bi_directional_nat(self):
        pass # TODO

class Test_Blocked_But_Should_Be_Allowed(unittest.TestCase):
    def test_acl_shadowed(self):
        pass  # TODO

    def explicit_acl_drop_packets(self):
        pass # TODO

    def test_interface_mismatch_vlan_tagging(self):
        pass # TODO

    def test_static_route_sends_pkts_the_wrong_way(self):
        pass # TODO

if __name__ == '__main__':
    unittest.main()