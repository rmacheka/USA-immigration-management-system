from setuptools import setup, find_packages

setup(
    name="immigration-system",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "PyJWT",
        "python-jose[cryptography]",
        "passlib[bcrypt]",
        "sqlalchemy",
    ],
) 