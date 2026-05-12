from setuptools import setup, find_packages

setup(
    name="ktc-mail",
    version="0.2.0",
    description="KTC Mail — bare-metal Debian/Ubuntu mail server suite",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
)
