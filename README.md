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

### Frontend

Authorization flow depends on `mpad.js` browser library. To show login button:

* Put div with distinct ID where login button should be
* Create authorization URL by using `get_login_url(handler)` server side
* At the end of page body load `mpad.js` with parameters `data-authurl`
(authorization URL) and `data-element` (login button ID)

```
<script src="https://demo.dev.miracl.net/mpin/mpad.js" data-authurl="{{ auth_url }}" data-element="btmpin"></script>
```

### MiraclMixin

Contains all logic for authentication flow. Mixin uses `RequestHandler`
functionality for state preservation and request handling.

Notable methods:
* `on_auth_success` and `on_auth_failed` - abstract methods that are called
on authentication events.
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
authentification flow. It calls `perform_login_redirect` method internally.
To start authentication flow, get authentication URL by using
`get_login_url(handler)`. Returned URL should be used with `mpad.js` (see
[Frontend](#markdown-header-frontend)). After user interaction
method `on_auth_success` or `on_auth_failed` will be called.

See settings, `on_auth_success` and `on_auth_failed` description of
`MiraclMixin` for additional details.

### Additional methods

There are some helper methods that can be called from any RequestHandler:

`is_authenticated` checks if token is saved in secure cookie.

`logout` clears token from cookie.

`refresh_user_data` clears user info and re-retrieves it from server. It can
change authentification state if access token is expired. This is coroutine.

`get_user_id` and `get_email` returns cached user information.

`get_login_url` generates authorization URL for `mpad.js`

`set_issuer` sets issuer URL. It needs to be called before constructing
handlers.

## Samples

Configuration is located in `miracl.json`.

Replace `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URI` with valid data from
Miracl. Samples can be run after setup step is done.

Redirect URI for this sample is `http://127.0.0.1:5000/c2id` if run locally.
