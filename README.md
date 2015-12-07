# Apache CAS Authentication Module

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

> <http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Introduction

The purpose of this module is to allow an Apache web server to interact
with an authentication server that conforms to the CAS version 1 or 2
protocol as specified by Yale/JA-SIG.  At the time of this writing, the CAS
protocol specification is here:

> <http://www.ja-sig.org/products/cas/overview/protocol/index.html>

## Quickstart Installation

The following development libraries and utilities must be installed:

* OpenSSL - 0.9.8c
* Apache Portable Runtime - 1.2.8
* Apache Portable Runtime Utilities - 1.2.7
* Apache Web Server - 2.2.3
* libcurl - 7.18.2
* libpcre - 7.8

Download the distribution via git or tarball, and use the standard
Autoconf incantation:

```console
./configure && make && sudo make install
```

Edit your Apache configuration to load the mod_auth_cas module:

```apache
LoadModule auth_cas_module /path/to/mod_auth_cas.so
```

Set a few required parameters in your Apache configuration:

```apache
CASCookiePath /var/cache/apache2/mod_auth_cas/
CASLoginURL https://login.example.org/cas/login
CASValidateURL https://login.example.org/cas/serviceValidate
```

Protect a "Location" or "Directory" block in your Apache
configuration:

```apache
<Location /secured>
    Authtype CAS
    require valid-user
<Location>
```

If SAML-delivered attribute authorization is also desired, use the
`samlValidate` URL, enable SAML validation, and specify `cas-attribute`
in your require rule (please note: both attribute name and value are
case-sensitive):

```apache
CASCookiePath /var/cache/apache2/mod_auth_cas/
CASLoginURL https://login.example.org/cas/login
CASValidateURL https://login.example.org/cas/samlValidate
CASValidateSAML On

<Location /secured>
    Authtype CAS
    require cas-attribute edupersonaffiliation:staff
</Location>
```

## New Features & Functions in this Release

* Unit tests added for a significant portion of functionality.
* Improved automake support.
* `CASValidateServer` functionality has been removed.  Users must
  either fix their SSL certificate configuration using the
  CASCertificatePath directive, or switch to communicating with
  the CAS server over standard HTTP.
* `CASAllowWildcardCert` has been removed, as this has been a no-op for
  some time (libcurl handles all validation).

## Bug Fixes

* Fixed security bug impacting users of CAS attributes in a CGI
  environment (MAS-62) reported by Josh Hoyt.
* Assorted other stability fixes.

## Known Limitations

These limitations are known to exists in this release of the software:

* CAS Proxy Validation is not implemented in this version.
* CAS Ticket Validation can only be performed over an SSL connection.
  The CAS protocol does not explicitly require this, but to not do so
  leaves this system open to a man-in-the-middle attack.
* CAS single sign out is currently not functional and disabled.  It
  is only safe to use in the case where all requests are GET and not
  POST (the module inadvertently 'eats' some content of the POST
  request while determining if it should process it as a SAML logout
  request).
* Reports of slow performance on some systems (particularly
  virtual machines) have been reported.  This is related to the
  entropy that is gathered when creating a session cookie for
  the end user.  To combat this, there are 3 solutions.  The
  first is to upgrade the version of the Apache Portable Runtime
  on your system to >= 1.3.0.  In that version, entropy is gathered
  from a nonblocking source.  The second method would be to install
  a package such as rng-tools and feed random data from `/dev/urandom`
  to /dev/random("-r /dev/urandom").  The  last way is to reduce
  the size of the `CASCookieEntropy` setting, reducing the demand on
  the pool.
* Win32 support has been dropped (but not removed) due to lack of
  development resources, and seemingly minimal community usage.
  You are welcome to try it, but YMMV for success.

## GETTING STARTED

### Docker

This package includes a `Dockerfile` that can be used to quickly
spin up a development environment with [Docker](http://www.docker.com).
Simple build the docker container with (Note that you must be in the directory
containing the `Dockerfile`):

```console
docker build -t mod_auth_cas-dev .
```

Then you can run the container with:

```console
docker run -ti -v /path/to/project/root:/data:Z mod_auth_cas-dev
```

The container includes a full Ubuntu based toolchain and all the
dependencies required for the project.

### SOFTWARE DEPENDENCIES

The module was built and tested on the following libraries/versions:

* OpenSSL - 0.9.8c
* Apache Portable Runtime - 1.2.8
* Apache Portable Runtime Utilities - 1.2.7
* Apache Web Server - 2.2.3
* libcurl - 7.18.2

Additionally, GNU Make and the auto* tools are necessary for building
`mod_auth_cas`.

Compatibility with other versions will depend on those other libraries.

To develop/test mod_auth_cas, the following Debian packages are necessary:
* apache2-threaded-dev
* autoconf
* automake
* check
* libapr1-dev
* libaprutil1-dev
* libcurl4-openssl-dev
* make
* pkg-config

(this list should not be considered exhaustive)

### INSTALLATION INSTRUCTIONS

Ensure that the follow files are in the working directory:

```
mod_auth_cas.c
mod_auth_cas.h
```

### COMPILE INSTRUCTIONS

Use the Apache eXtenSion tool (APXS) to compile and install this
object as a dynamically shared object (DSO), by either:

`apxs -i -lssl -lcurl -c mod_auth_cas.c`
or
`apxs2 -i -lssl -lcurl -c mod_auth_cas.c`

depending on your Linux distribution.

This release of mod_auth_cas includes support for autoconf.  Note that
you must use GNU Make - other Make implementations may work, but are
untested and not recommended.  Use the standard commands below to
compile and install:

```console
./configure; make; make install
```

configure can take an optional `--with-apxs=/path/to/apxs argument` to
specify the path to your APXS binary.

### Configuring the Software

First, you must tell Apache to load the module.  In your `httpd.conf`,
add:

```apache
LoadModule auth_cas_module /path/to/mod_auth_cas.so
```

Then, in the location(s) you want to protect, use the following
directive:

```apache
AuthType CAS
```

Be sure to set authorization parameters in the locations you
are protecting (e.g. `require valid-user`, `require group foo`)

The following are valid configuration options and their default:

### Valid Server/VirtualHost Directives

Directive             | Default           | Description
--------------------- | ----------------- | -----------
`CASVersion`            | 2                 | The version of the CAS protocol to adhere to (1 or 2). This affects whether Gateway mode is available and how the CAS validation response is parsed.
`CASDebug`              | Off               | Enable or disable debugging mode for troubleshooting.  Please note that LogLevel must be set to Debug for the VirtualHost in order for these logs to be visible.  
`CASValidateDepth`      | 9                 | This directive will set the maximum depth for chained certificate validation.  The default (according to OpenSSL documentation) is 9.
`CASCertificatePath`    | /etc/ssl/certs/   | The path to the X509 certificate of the Certificate Authority for the server in `CASLoginURL` and `CASValidateURL`. This may be either a file, or a directory containing the certificate files linked to by their hashed names.
`CASLoginURL`           | NULL              | The URL to redirect users to when they attempt to access a CAS protected resource and do not have an existing session. The `service`, `renew`, and `gateway` parameters will be appended to this by mod_auth_cas if necessary. Include `http[s]://...`
`CASValidateURL`        | NULL              | The URL to use when validating a ticket presented by a client in the HTTP query string (`ticket=...`).  Must include `https://` and must be an HTTPS URL.
`CASLogoutURL`          | NULL              | Optional. The URL to use when logging the user out of the CAS system. Must include `http[s]://`.
`CASLogoutHandlerURL`   | NULL              | Required only if `CASLogoutURL` is used. Local url at which to handle logout calls. Requests with a valid session made to this URL will cause the session to be terminated and the user to be directed to `CASLogoutURL` if it's set.
`CASProxyValidateURL`   | NULL              | The URL to use when performing a proxy validation. This is currently an unimplemented feature, so setting this will have no effect.
`CASRootProxiedAs`      | NULL              | This URL represents the URL that end users may see in the event that access to this Apache server is proxied.  This will override the automatic generation of service URLs and construct them using this prefix.  As an example: If the site being protected is <http://example.com/> and the Apache instance of this server is <http://internal.example.com:8080>, setting `CASRootProxiedAs` to <http://example.com> would result in proper service parameter generation.
`CASCookiePath`         | /dev/null         | When users first authenticate to mod_auth_cas with a valid service ticket, a local session is established.  Information about this session (the username, time of creation, last activity time, the resource initially requested, and whether or not the credentials were renewed) is stored in this directory. This location should be writable by the web server ONLY. Any user that can write to this location can falsify authentication information by creating a fake data file. NOTE: Some distributions purge the contents of `/tmp/` on a reboot, including user created directories.  This will prevent mod_auth_cas from storing cookie information until that directory is created. To avoid this, try using a different location, such as `/var/cache/apache2/mod_auth_cas/`
`CASCookieEntropy`      | 32                | When creating a local session, this many random bytes are used to create a unique session identifier.  Using large values for this field may result in delays when generating session IDs if not enough entropy is available.
`CASTimeout`            | 7200 (2 hours)    | This is the hard limit, in seconds, for a mod_auth_cas session (whether it is idle or not).  When a session has reached this age and a new request is made, the user is redirected to the `CASLoginURL` to obtain a new service ticket.  When this new ticket is validated, they will be assigned a new mod_auth_cas session.  Set this value to '0' in order to allow a non-idle session to not expire.
`CASIdleTimeout`        | 3600 (1 hour)     | This is a limit, in seconds, of how long a mod_auth_cas session can be idle. When a request comes in, if it has been inactive for `CASIdleTimeout` seconds, the user is redirected to the `CASLoginURL` to obtain a new service ticket.
`CASCacheCleanInterval` | 1800 (30 minutes) | This is the minimum amount of time that must pass in between cache cleanings. When a new ticket is issued, or when an expired session is presented, the time of the last cache clean is compared against this value. If `CASCacheCleanInterval` seconds have passed since the last cleaning, then all files in `CASCookiePath` are examined and if they have expired, they are removed.  This is merely to prevent the file system from becoming excessively cluttered.
`CASCookieDomain`       | NULL              | Specify the value for the `Domain=` parameter in the Set-Cookie header.
`CASCookieHttpOnly`     | On                | Set the optional `HttpOnly` flag for cookies issues by mod_auth_cas. Set the HttpOnly flag as described in in RFC 6265. This flag prevents the mod_auth_cas cookies from being accessed by client side Javascript.
`CASAuthoritative`      | Off               | This directive determines whether an optional authorization directive (see 'Require cas-attribute') is authoritative and thus binding or if other authorization modules will also be applied. `On` means authoritative, `Off` means not authoritative.

### Valid Directory/.htaccess Directives

Directive              | Default           | Description
---------------------- | ----------------- | -----------
`CASScope`               | Off               | Use this directive with an argument as a relative path (e.g. `/application/`) to specify the scope for which a mod_auth_cas cookie is valid.  This is beneficial to prevent additional round trips to the CAS server. Assume someone authenticates to `/application/subdir/` and then browses to `/application/` - without `CASScope` set, each request would result in a round trip to the CAS server and a new cookie being created (one for each directory). `CASScope` would set one cookie, which will be presented on access to both directories. Note that if someone accessed `/application/` and then `/application/subdir/` this would not be an issue, but that order of access can not be guaranteed. To disable this feature, the special argument `Off` will return to per-directory cookie paths for this directory and subdirectories.
`CASRenew`               | Off               | Use this directive with an argument as a relative path (e.g. `/application/secure/` for `http://www.example.com/application/secure/*`) to force a user to renew their credentials when accessing that directory. The argument MUST be a relative path. To disable this requirement, the special argument `Off` will disable this requirement for this directory and subdirectories.
CASGateway             | Off               | Use this directive with an argument as a relative path (e.g. `/application/insecure/` for `http://www.example.com/application/insecure/*`) to allow anonymous access to that directory. The argument MUST be a relative path. To disable this feature, the special argument `Off` will reinstate the requirement for authentication.
`CASCookie`            | MOD_AUTH_CAS      | The name of the cookie used to store the session ID over HTTP connections. It should be changed if it will interfere with the application protected by mod_auth_cas.
`CASSecureCookie`       | MOD_AUTH_CAS_S    | The name of the cookie used to store the session ID over HTTPS connections. It should be changed if it will interfere with the application protected by mod_auth_cas.
`CASGatewayCookie`      | MOD_AUTH_CAS_G    | The name of the cookie used to store whether or not the user has attempted to access this resource before. It should be changed if it will interfere with the application protected by mod_auth_cas.
`CASAuthNHeader`         | None              | If enabled, this will store the user returned by CAS in an HTTP header accessible to your web applications.
`CASSSOEnabled`          | Off               | If enabled, this activates support for Single Sign Out within the CAS protocol. Please note that this feature is currently experimental and may mangle POST data.
`CASValidateSAML `       | Off               | If enabled, the response from the CAS Server will be parsed for SAML attributes which will be associated with the user.
`CASAttributePrefix `    | CAS_              | mod_auth_cas will add a header named  `<CASAttributePrefix><attr_name>` with the value of this header being the attribute values when SAML validation is enabled.
`CASAttributeDelimiter`  | ,                 | mod_auth_cas will set the value of the attribute header (as described in `CASAttributePrefix`) to `<attrvalue><CASAttributeDelimiter><attrvalue>` in the case of multiple attribute values.
`CASScrubRequestHeaders` | Off               | mod_auth_cas will strip request inbound request headers that may have special meaning, such as those set with the `CASAttributePrefix` or the `CASAuthNHeader` value.
`Require cas-attribute <attribute>:<value>` | NULL | Use this directive to authorize based on SAML cas attributes returned via the session validation call. Multiple directives are OR-ed. If directive is present with no attributes defined, the request is declined. If value has spaces, wrap the pair in quotes. See also `CASAuthoritative`.
`Require cas-attribute <attribute>~<value>` | NULL | Use this form of the directive to authorize based on SAML cas attributes returned via the session validation call. Multiple directives are OR-ed. If directive is present with no attributes defined, the request is declined. The value is interpreted as a Perl-Compatible Regular Expression (PCRE) using case-sensitive matching. See also `CASAuthoritative`.

## Contact Information & Website

We welcome your feedback, suggestions and contributions. Contact us
via email if you have questions, feedback, code submissions,
and bug reports.  To reach the development team, send an e-mail to:

```
mod-auth-cas-dev [at] lists [dot] jasig [dot] org
```
