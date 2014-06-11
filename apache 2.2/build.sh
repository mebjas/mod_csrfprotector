# MOD_CSRFPROTECTOR  - Apache 2.2.x module for mitigating CSRF vulnerabilities
#						In web applications

clear
APACHE_VER=2.2.2
echo "Building for apache version $APACHE_VER"
echo "BUILD INIT...."
echo "Initiating MOD_CSRFPROTECTOR BUILD PROCESS"
sudo apxs2 -cia -n csrf_protector ./src/mod_csrfprotector.c
echo "BUILD FINISHED ...!"
echo "Restarting APACHE ...!"
sudo service apache2 restart
echo "mod_csrfprotector has been compiled, installed and activated"
