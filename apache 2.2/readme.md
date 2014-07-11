APACHE 2.2 MOD_CSRFProtector configuration
==========================================


These configurations shall be added to `apache.conf` generally available at `/etc/apache2/` directory    


Configurations
===============

config name | description | example
----------- | ----------- | -------
**csrfpEnable** | csrfpEnable 'on'\'off', enables the module. Default is 'on' | csrfpEnable on
**csrfpAction** | Defines Action to be taken in case of failed validation | csrfpAction forbidden
**errorRedirectionUri** | Defines URL to redirect if action = `redirect` | errorRedirectionUri "http://somesite.com/error.html"
**errorCustomMessage** | Defines Custom Error Message if action = `message` | errorCustomMessage "ACCESS BLOCKED BY OWASP CSRFP"
**jsFilePath** | Absolute url of the js file | jsFilePath http://somesite.com/csrfp/csrfprotector.js
**tokenLength** | Defines length of csrfp_token in cookie | tokenLength 20
**disablesJsMessage** | `<noscript>` message to be shown to user | disablesJsMessage "Please enable javascript for CSRF Protector to work"
**verifyGetFor** | Pattern of urls for which GET request CSRF validation is enabled (Multiple allowed) | verifyGetFor `*://*/*`

How to modify configurations
============================
in `apache.conf` add these lines (Example configuration, Note: your config needs may be different)
```sh
#Configuration for CSRFProtector
csrfpEnable on
csrfpAction forbidden
errorRedirectionUri ""
errorCustomMessage "Access forbidden by OWASP CSRFProtector"
jsFilePath "https://raw.githubusercontent.com/mebjas/mod_csrfprotector/master/js/csrfprotector.js"
tokenLength 20
disablesJsMessage ""
verifyGetFor .*:\/\/localhost\/admin/.*
verifyGetFor .*:\/\/localhost\/user/delete.*

```

then reload `apache2` using `sudo service apache2 restart` in a terminal window
