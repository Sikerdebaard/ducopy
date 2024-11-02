from setuptools import setup, find_packages


def get_version() -> str:
    with open("VERSION", encoding="utf-8") as f:
        return f.read().strip()


def read_requirements(filename: str) -> list[str]:
    with open(filename, encoding="utf-8") as f:
        return f.read().splitlines()


setup(
    name="ducopy",
    version=get_version(),
    description="A brief description of your app",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Thomas Phil",
    author_email="thomas@tphil.nl",
    url="https://github.com/sikerdebaard/ducopy",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=read_requirements("requirements.txt"),
    extras_require={"dev": read_requirements("requirements_dev.txt") + ["pytest>=6.0"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "ducopy=ducopy.__main__:main",
        ],
    },
)
