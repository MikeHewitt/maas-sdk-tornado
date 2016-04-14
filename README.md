# Setup

Use `python setup.py` for setup. It uses python-setuptools.

Some dependencies require additional system packages to be installed.
For Ubuntu 14.04 dependencies are:

* `build-essential` (for compiling code in dependencies)
* `python-dev` or `python3-dev` (depending on python version used)
* `libssl-dev`
* `libffi-dev`
* `python-setuptools`

## Installation

`python setup.py install`

## Development setup

`python setup.py develop` will install package using symlink to source code.

# Miracl API

## Samples

Replace `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URI` with valid data from
https://m-pin.my.id/protected . Samples can be run after setup step is done.
