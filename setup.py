import re

from setuptools import setup, find_packages


def _get_version() -> str:
    """Read version from ``__init__.py`` — single source of truth."""
    with open("src/ktc_mail_admin/__init__.py") as f:
        m = re.search(r'__version__\s*=\s*"([^"]+)"', f.read())
        if not m:
            raise RuntimeError("version not found in __init__.py")
        return m.group(1)


setup(
    name="ktc-mail",
    version=_get_version(),
    description="KTC Mail — bare-metal Debian/Ubuntu mail server suite",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "ktc_mail_admin": ["templates/*.html"],
    },
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.20.0",
        "jinja2>=3.0.0",
        "itsdangerous>=2.0.0",
        "qrcode>=7.0",
        "redis>=4.5.0",
    ],
    extras_require={
        "dev": [],
    },
)
