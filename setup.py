import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="windbgtool-ohjeongwook",
    version="1.0",
    author="Matt Oh",
    author_email="jeongoh@darungrim.com",
    description="WinDbg Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ohjeongwook/windbgtool",
    packages=setuptools.find_packages(),
    install_requires=[
        'pykd',
        'capstone',
        #'pyvex',
        'archinfo',
        'cffi',
        'idatool-ohjeongwook @ git+https://github.com/ohjeongwook/idatool@v1.0#egg=idatool-ohjeongwook',
    ],    
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=2.7',
)
