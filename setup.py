from setuptools import setup, find_packages

setup(
    name="pyfrost",
    version="0.2.1",
    packages=find_packages(exclude=["pyfrost/tests", "pyfrost/example"]),
)
