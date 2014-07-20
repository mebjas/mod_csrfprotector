# MOD_CSRFPROTECTOR  - Apache 2.2.x module for mitigating CSRF vulnerabilities
#                        In web applications

clear
APACHE_VER=2.2.2
echo "Building for apache version $APACHE_VER"
echo "BUILD INIT...."
echo "Initiating MOD_CSRFPROTECTOR BUILD PROCESS"
sudo apxs2 -cia -n csrf_protector ./src/mod_csrfprotector.c ./src/sqlite/sqlite3.c -lssl -lcrypto
echo "BUILD FINISHED ...!"
echo "Restarting APACHE ...!"

echo "---------------------------------------------------"
echo "Appending default configurations to /etc/apache2/mods-enabled/csrf_protector.load"
echo "" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "#Configuration for CSRFProtector" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "<IfModule mod_csrfprotector.c>" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "    csrfpEnable on" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "    csrfpAction strip" >> /etc/apache2/mods-enabled/csrf_protector.load
#echo "    errorRedirectionUri \"\"" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "    errorCustomMessage \"<h2>Access forbidden by OWASP CSRFProtector</h2>\"" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "    jsFilePath http://localhost/csrfp_js/csrfprotector.js" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "    tokenLength 20" >> /etc/apache2/mods-enabled/csrf_protector.load
#echo "    disablesJsMessage \"\"" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "    verifyGetFor .*:\/\/localhost\/csrfp_test/delete.*" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "    verifyGetFor .*:\/\/localhost\/csrfp_custom/.*" >> /etc/apache2/mods-enabled/csrf_protector.load
echo "</IfModule>" >> /etc/apache2/mods-enabled/csrf_protector.load

echo "Configuration write finished"
echo "---------------------------------------------------"

sudo service apache2 restart
echo "mod_csrfprotector has been compiled, installed and activated"











