from setuptools import setup, find_packages

setup(
    name="pyfrost",
    version="0.1",
    packages=find_packages(exclude=["pyfrost/tests", "pyfrost/example"]),
    install_requires=[
        "fastecdsa==2.2.3",
        "Flask==3.0.0",
        "cryptography",
        "aiohttp==3.9.3",
    ],
)
