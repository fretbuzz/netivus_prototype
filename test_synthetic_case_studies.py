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

class Test_Reproduction(unittest.TestCase):
    def test_base_network_working_connectivity(self):
        NETWORK_NAME = "synthetic_base_network"
        SNAPSHOT_NAME = "synthetic_base_network"
        SNAPSHOT_PATH = "./synthetic_scenarios/base_Intenionet_network"

        type_of_problem = 'Connectivity_Allowed_And_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "22"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1[eth0]'
        end_location = 'host2[eth0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

        no_interactive_flag = True
        _,_, could_recreate_problem, should_we_debug_the_path_forward = main.main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip, desired_path, problematic_path,
             no_interactive_flag, type_of_problem, end_location, srcPort, dstPort, ipProtocol)

        self.assertEqual(could_recreate_problem, True)
        self.assertEqual(should_we_debug_the_path_forward, None)

    def test_base_network_blocked_connectivity(self):
        NETWORK_NAME = "synthetic_base_network"
        SNAPSHOT_NAME = "synthetic_base_network"
        SNAPSHOT_PATH = "./synthetic_scenarios/base_Intenionet_network"

        type_of_problem = 'Connectivity_Allowed_And_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "24"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1[eth0]'
        end_location = 'host2[eth0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

        no_interactive_flag = True
        _,_,could_recreate_problem, should_we_debug_the_path_forward = main.main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip,
                                           desired_path, problematic_path,
                                           no_interactive_flag, type_of_problem, end_location, srcPort, dstPort,
                                           ipProtocol)

        self.assertEqual(could_recreate_problem, False)
        self.assertEqual(should_we_debug_the_path_forward, False)

    #@mock.patch('module_under_test.input', create=True)
    def test_Allowed_But_Should_Be_Blocked__acl_shadowed(self):
        # output code from here: https://stackoverflow.com/questions/33767627/python-write-unittest-for-console-print
        # then input code can be @patch (for mock unittest) :: https://stackoverflow.com/questions/47690020/python-3-unit-tests-with-user-input
        #flowchart_algo.side_effect = ['Albert Einstein', '42.81', 'done'] # each time the module calls for input, it'll take the next value from this list (i.e. reads left to right, one val per input request)

        #capturedOutput = io.StringIO()  # Create StringIO object
        #sys.stdout = capturedOutput

        # TODO: put the actual function call here
        pass

        #sys.stdout = sys.__stdout__  # Reset redirect.
        #print('Captured', capturedOutput.getvalue())  # print the output, so that we can see it

        # TODO: write the tests for the output here

    def test_Allowed_But_Should_Be_Blocked__bi_directional_nat(self):
        pass # TODO

    def test_Blocked_But_Should_Be_Allowed__acl_shadowed(self):
        pass  # TODO

    def test_Blocked_But_Should_Be_Allowed__explicit_acl_drop_packets_foward(self):
        NETWORK_NAME = "synthetic_explicit_acl_drop_packets"
        SNAPSHOT_NAME = "synthetic_explicit_acl_drop_packets"
        SNAPSHOT_PATH = "./synthetic_scenarios/simple_errors_no_refinement/blocked_but_should_be_allowed/explicit_acl_drop_packets_forward"

        # problem info
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "22"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1[eth0]'
        end_location = 'host2[eth0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

        no_interactive_flag = True
        _,_,could_recreate_problem, should_we_debug_the_path_forward = main.main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip,
                                           desired_path, problematic_path,
                                           no_interactive_flag, type_of_problem, end_location, srcPort, dstPort,
                                           ipProtocol, return_after_recreation=True)

        self.assertEqual(could_recreate_problem, True)
        self.assertEqual(should_we_debug_the_path_forward, True)

    def test_Blocked_But_Should_Be_Allowed__explicit_acl_drop_packets_return(self):
        NETWORK_NAME = "synthetic_explicit_acl_drop_packets_return"
        SNAPSHOT_NAME = "synthetic_explicit_acl_drop_packets_return"
        SNAPSHOT_PATH = "./synthetic_scenarios/simple_errors_no_refinement/blocked_but_should_be_allowed/explicit_acl_drop_packets_return"

        # problem info
        type_of_problem = 'Connecitivity_Blocked_But_Should_Be_Allowed'
        src_ip = '2.128.0.101'
        dst_ip = '2.128.1.101'
        srcPort = "22"
        dstPort = "22"
        ipProtocol = 'tcp'
        start_location = 'host1[eth0]'
        end_location = 'host2[eth0]'
        desired_path = None  # Not needed for this type of problem
        problematic_path = None  # not needed by this system, for any task

        no_interactive_flag = True
        _,_,could_recreate_problem, should_we_debug_the_path_forward = main.main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH, start_location, dst_ip, src_ip,
                                           desired_path, problematic_path,
                                           no_interactive_flag, type_of_problem, end_location, srcPort, dstPort,
                                           ipProtocol, return_after_recreation=True)

        self.assertEqual(could_recreate_problem, True)
        self.assertEqual(should_we_debug_the_path_forward, False)

    def test_Blocked_But_Should_Be_Allowed__interface_mismatch_vlan_tagging(self):
        pass # TODO

    def test_Blocked_But_Should_Be_Allowed__static_route_sends_pkts_the_wrong_way(self):
        pass # TODO

if __name__ == '__main__':
    unittest.main()