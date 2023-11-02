from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey

import secrets

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
        self.coefficients: list[ECPrivateKey] = []
        
        # If an initial coefficient is provided, convert it to an integer from a hex string if necessary
        # and add it as the first coefficient of the polynomial.
        if coefficient0 is not None:
            if type(coefficient0) == str:
                coefficient0 = int(coefficient0, 16)
            self.coefficients.append(ECPrivateKey(coefficient0, curve))

        # Generate the remaining random coefficients such that the number of coefficients
        # matches the threshold value.
        for _ in range(threshold - len(self.coefficients)):
            self.coefficients.append(
                ECPrivateKey(secrets.randbits(32*8), curve))

    def evaluate(self, x: int) -> ECPrivateKey:
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
            result += self.coefficients[i].d * pow(x, i)

        # Return the result as an elliptic curve private key.
        return ECPrivateKey(result, self.curve)

    def coef_pub_keys(self) -> list[ECPublicKey]:
        """
        Retrieves the public keys corresponding to the private coefficient keys.

        Returns:
            list[ECPublicKey]: A list of elliptic curve public keys corresponding
                               to the coefficients of the polynomial.
        """
        result = []
        for coefficient in self.coefficients:
            # Convert each private key coefficient to its corresponding public key.
            result.append(coefficient.get_public_key())
        return result
