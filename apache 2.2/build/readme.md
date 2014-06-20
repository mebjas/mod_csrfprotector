How to use this dynamic library
=====================

<h4> Ubuntu (linux) </h4>
Download `mod_csrfprotector.so` and move it to `usr/libs/apache2/modules`<br>
`Note: You'll need root access to do so`

--------------------------------------------


At `etc/apache2/mods-enabled/` create a file `csrf_protector.load` and add
```
LoadModule csrf_protector modules/mod_csrfprotector.so
```
Or add these lines directly to `apache.conf` at `etc/apache2/`

---------------------------------------------

For addition configurations you might want like to add config like

```
#Configuration for CSRFProtector
csrfpEnable on
csrfpAction forbidden
errorRedirectionUri "-"
errorCustomMessage "Access forbidden by OWASP CSRFProtector"
jsFilePath http://localhost/
tokenLength 20
disablesJsMessage "-"
verifyGetFor (.*):\/\/(.*)\/(.*)
```


Refer [configuration_info](https://github.com/mebjas/mod_csrfprotector/blob/master/apache%202.2/readme.md) for more information on config file

----------------------------------------------
Now restart apache after this
```
service apache2 restart
```
in terminal
