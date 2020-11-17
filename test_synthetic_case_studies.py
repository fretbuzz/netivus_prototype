import unittest

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
    def test_acl_shadowed(self):
        #


        pass # TODO

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