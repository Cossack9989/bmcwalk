from setuptools import setup, find_packages


setup(
    name="bmcwalk",
    version="0.1",
    description="MegaRAC Firmware analysis tool",
    author_email="c0ss4ck9989@gmail.com",
    python_requires=">=3",
    scripts=[
        "bmcwalk-scan.py"
    ],
    packages=find_packages(),
    install_requires=[
        "loguru", "numpy", "xxhash", "magika", "r2pipe", "PyYAML", "fdt"
    ],
    # include_package_data=True,
    package_data={
        'bmcwalk': ['rules/*.yml', 'rules/semgrep/*.yml', 'rules/common/*.py']
    }
)
