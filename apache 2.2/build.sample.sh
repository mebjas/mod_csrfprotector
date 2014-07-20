# MOD_CSRFPROTECTOR  - Apache 2.2.x module for mitigating CSRF vulnerabilities
#						In web applications

reset
APACHE_VER=2.2.2
jsFileURL=https://raw.githubusercontent.com/mebjas/mod_csrfprotector/master/js/csrfprotector.js
jsFileName=csrfprotector.js

echo "Building for apache version $APACHE_VER"
echo "BUILD INIT...."
echo "Initiating MOD_CSRFPROTECTOR BUILD PROCESS"
sudo apxs2 -cia -n csrf_protector ./src/mod_csrfprotector.c ./src/sqlite/sqlite3.c -lssl -lcrypto
echo "BUILD FINISHED ...!"

echo "---------------------------------------------------"
echo "Appending default configurations to /etc/apache2/mods-enabled/csrf_protector.load"
echo "" | tee -a /etc/apache2/mods-enabled/csrf_protector.load

echo "a Javascript code need to be downloaded for this module to work"
echo -n "Enter the directory you want to download javascript file at:"
read path

echo "---------------------------------------------------"
echo "Downloading file to $path"
wget $jsFileURL
echo "Download finished"
chmod 644 $jsFileName
echo "chmod 644 $jsFileName"
cp $jsFileName $path
echo "$jsFileName copied to $path"
rm $jsFileName
echo "$jsFileName removed from current directory"
echo "Enter the absolute url for the javascript as it would appear to users"
echo "For example http://example.com/csrfp/$jsFileName"
echo -n ""
read jsFileAbsURL
echo "---------------------------------------------------"


echo "#Configuration for CSRFProtector" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
echo "csrfpEnable on" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
echo "csrfpAction forbidden" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
#echo "errorRedirectionUri \"\"" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
echo "errorCustomMessage \"<h2>Access forbidden by OWASP CSRFProtector</h2>\"" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
echo "jsFilePath $jsFileAbsURL" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
echo "tokenLength 20" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
#echo "disablesJsMessage \"\"" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
echo "verifyGetFor .*:\/\/localhost\/csrfp_test/delete.*" | tee -a /etc/apache2/mods-enabled/csrf_protector.load
echo "verifyGetFor .*:\/\/localhost\/csrfp_custom/.*" | tee -a /etc/apache2/mods-enabled/csrf_protector.load


echo "Configuration write finished"
echo "---------------------------------------------------"

echo "Restarting APACHE ...!"
sudo apachectl restart || sudo apachectl start
echo "mod_csrfprotector has been compiled, installed and activated"











