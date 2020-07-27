import unittest
import main


class TestSum(unittest.TestCase):

    def test_sum(self):
        self.assertEqual(sum([1, 2, 3]), 6, "Should be 6")

    def test_sum_tuple(self):
        self.assertEqual(sum((1, 2, 2)), 5, "Should be 5")

    def test_mocked(self):
        # following here: https://code-maven.com/mocking-input-and-output-for-python-testing
        input_values = [2, 3, 3, 4, 5]
        output = []

        def mock_input(s):
            output.append(s)
            return input_values.pop(0)

        main.input = mock_input
        #main.print = lambda s: output.append(s)
        NETWORK_NAME = "example_network"
        SNAPSHOT_NAME = "example_snapshot"
        SNAPSHOT_PATH = "./scenarios/Access port config"

        G_layer_2, G_layer_3 = main.main(NETWORK_NAME, SNAPSHOT_NAME, SNAPSHOT_PATH)

        # TODO: need to make sure that this thing is reproducibile/testable

if __name__ == '__main__':
    unittest.main()