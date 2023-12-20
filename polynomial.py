from fastecdsa import keys
from fastecdsa.point import Point
from fastecdsa.curve import Curve
from typing import List


class Polynomial:
    """
    A class representing a polynomial for use in cryptographic schemes such as
    Shamir's Secret Sharing and Threshold Signature Scheme. This polynomial is 
    defined over a given elliptic curve.

    Attributes:
        threshold (int): The minimum number of points needed to reconstruct
                         the polynomial. (The degree of polynomial + 1)
        curve (Curve): The elliptic curve over which the polynomial is defined.
        coefficients (list[ECPrivateKey]): The list of coefficients as elliptic
                                            curve private keys.

    Methods:
        calculate(x): Evaluates the polynomial at a given point x.
        coef_pub_keys(): Returns the public keys corresponding to the private
                         coefficient keys.
    """

    def __init__(self, threshold: int, curve: Curve, coefficient0: str = None) -> None:
        """
        Initializes the Polynomial instance.

        Parameters:
            threshold (int): The threshold number of shares needed to reconstruct
                             the polynomial. (The degree of polynomial + 1)
            curve (Curve): The elliptic curve over which the polynomial is defined.
            coefficient0 (str, optional): The first coefficient of the polynomial,
                                          represented as a hexadecimal string. If not
                                          provided, a random coefficient will be generated.
        """
        self.threshold: int = threshold
        self.curve: Curve = curve
        self.coefficients: List[int] = []

        # If an initial coefficient is provided, convert it to an integer from a hex string if necessary
        # and add it as the first coefficient of the polynomial.
        if coefficient0 is not None:
            if type(coefficient0) == str:
                coefficient0 = int(coefficient0, 16)
            self.coefficients.append(coefficient0)

        # Generate the remaining random coefficients such that the number of coefficients
        # matches the threshold value.
        for _ in range(threshold - len(self.coefficients)):
            self.coefficients.append(keys.gen_private_key(self.curve))

    def evaluate(self, x: int) -> int:
        """
        Evaluates the polynomial at a given point x.

        Parameters:
            x (int): The x-value at which to evaluate the polynomial.

        Returns:
            ECPrivateKey: The evaluation of the polynomial at point x, represented as
                          an elliptic curve private key.
        """
        result = 0
        # Convert x to an integer if it is provided as a string.
        if type(x) == str:
            x = int(x)

        # Evaluate the polynomial using Horner's method for efficiency.
        for i in range(len(self.coefficients)):
            result += self.coefficients[i] * pow(x, i)

        # Return the result as an elliptic curve private key.
        return result

    def coef_pub_keys(self) -> List[Point]:
        """
        Retrieves the public keys corresponding to the private coefficient keys.

        Returns:
            list[ECPublicKey]: A list of elliptic curve public keys corresponding
                               to the coefficients of the polynomial.
        """
        result = []
        for coefficient in self.coefficients:
            # Convert each private key coefficient to its corresponding public key.
            result.append(keys.get_public_key(coefficient, self.curve))
        return result
