from setuptools import setup, find_packages

setup(
    name="pyfrost",
    version="0.2.1",
    packages=find_packages(exclude=["pyfrost/tests", "pyfrost/example"]),
    install_requires=[
        "fastecdsa==2.3.2",
        "Flask==3.0.0",
        "cryptography",
        "aiohttp==3.9.3",
        "bitcoin-utils==0.6.8",
        "eth_abi==5.1.0"
    ],
)
