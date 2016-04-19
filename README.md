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

## Structure

### MiraclMixin

Contains all logic for authentication flow. Mixin uses `RequestHandler`
functionality for state preservation and request handling.

Notable methods:
* `on_auth_success` and `on_auth_failed` - abstract methods that are called
on authentication events.
* `perform_login_redirect` - performs redirect to Miracl system for
authentication. Method should be called when starting authentication.
* `perform_access_token_request` - performs request for access token and user
details. Method should be called when callback from Miracl system happens and
it contains code. Method will call `on_auth_success` or `on_auth_failed`
method depending on request result. This is coroutine.

Settings:
`MiraclMixin` uses web application settings with key `miracl`. Settings
structure:
```
'miracl': {
    'client_id': 'CLIENT_ID',
    'secret': 'CLIENT_SECRET',
    'redirect_uri': 'REDIRECT_URL',
}
```
All settings are required for `MiraclMixin` to work correctly.

### MiraclAuthRequestHandler

Inherits `MiraclMixin` and is default implementation of `RequestHandler` for
authentification flow. It calls `perform_access_token_request` and
`perform_login_redirect` methods internally. To start authentication flow
handler needs to receive get request with `login` parameter.

See settings, `on_auth_success` and `on_auth_failed` description of
`MiraclMixin` for additional details.

### Additional methods

There are some helper methods that can be called from any RequestHandler:

`is_authenticated` checks if token is saved in secure cookie.

`logout` clears token from cookie.

## Samples

Replace `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URI` with valid data from
https://m-pin.my.id/protected . Samples can be run after setup step is done.
