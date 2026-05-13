from setuptools import setup, find_packages

setup(
    name="ktc-mail",
    version="0.3.0",
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
    ],
    extras_require={
        "dev": [],
    },
)
