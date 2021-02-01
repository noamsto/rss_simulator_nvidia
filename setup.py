"""Setup module."""
import setuptools

setuptools.setup(
    name="rss-simulator-nvidia",
    version="0.0.2",
    author="Noam Stolero",
    author_email="noams@nvidia.com",
    license="MIT",
    description="A tool for simulating Toeplitz hash function.",
    url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_packages(),
    python_requires=">=2.7",
    install_requires=["matplotlib>=2.2.5", "pandas>=0.24.2", "enum34>=1.1.10"],
    entry_points = {
        'console_scripts': ['rss-simulator=rss_simulator:main'],
    }
)
