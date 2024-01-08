import unittest

if __name__ == "__main__":
    # Discover and run all tests in the 'tests' directory
    test_suite = unittest.TestLoader().discover('pyfrost/tests')
    unittest.TextTestRunner(verbosity=2).run(test_suite)
