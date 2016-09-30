# maas-sdk-tornado

[![Master Build Status](https://secure.travis-ci.org/miracl/maas-sdk-tornado.png?branch=master)](https://travis-ci.org/miracl/maas-sdk-tornado?branch=master)
[![Master Coverage Status](https://coveralls.io/repos/miracl/maas-sdk-tornado/badge.svg?branch=master&service=github)](https://coveralls.io/github/miracl/maas-sdk-tornado?branch=master)

* **category**:    SDK
* **copyright**:   2016 MIRACL UK LTD
* **license**:     ASL 2.0 - http://www.apache.org/licenses/LICENSE-2.0
* **link**:        https://github.com/miracl/maas-sdk-tornado

## Description

Tornado version of the Software Development Kit (SDK) for MPin-As-A-Service (MAAS).


## Setup

Run `python setup.py` for setup. It uses python-setuptools.

Some dependencies require additional system packages to be installed.
For Ubuntu 14.04 the dependencies are:

* `build-essential` (for compiling code in dependencies)
* `python-dev` or `python3-dev` (depending on python version used)
* `libssl-dev`
* `libffi-dev`
* `python-setuptools`

## Installation

`python setup.py install`

## Development setup

`python setup.py develop` will install the package using a symlink to the source code.

# Miracl API

## Structure

### Frontend

The authorization flow depends on the `mpad.js` browser library. To show the login button:

* Insert a div with a distinct ID where the login button is to appear
* Use `get_login_url(handler)` server side to generate the authorization URL
* At the end of page body load `mpad.js` with the parameters `data-authurl`
(authorization URL) and `data-element` (login button ID)

```
<script src="<<Insert correct mpad url here>>" data-authurl="{{ auth_url }}" data-element="btmpin"></script>
```

Please refer to your distributor-specific documentation to find the correct url for the mpad.js `script src`

### MiraclMixin

Contains all logic for the authentication flow. Uses `RequestHandler`
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

Inherits `MiraclMixin` and is the default implementation of `RequestHandler` for
authentification flow. It calls the `perform_login_redirect` method internally.
To start the authentication flow, obtain the authentication URL with
`get_login_url(handler)`. The returned URL should then be used with `mpad.js` (see
[Frontend](#markdown-header-frontend)). After user interaction with the login button, the
methods `on_auth_success` or `on_auth_failed` will be called.

### Additional methods

There are some helper methods that can be called from any RequestHandler:

`is_authenticated` checks if token is saved in a secure cookie.

`logout` clears token from the cookie.

`refresh_user_data` clears user info and re-retrieves it from server. It can
change authentification state if access token is expired. This is coroutine.

`get_user_id` and `get_email` returns cached user information.

`get_login_url` generates the authorization URL for `mpad.js`

`set_issuer` sets issuer URL. It needs to be called before constructing
handlers.

## Sample App

In the `samples` directory, `miracl.json` contains the app credentials config. Replace `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URI` with valid data for your app. The sample app can then be run.

Redirect URI for this sample is `http://127.0.0.1:5000/c2id` if run locally.
