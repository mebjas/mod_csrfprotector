# MOD_CSRFPROTECTOR  - Apache 2.2.x module for mitigating CSRF vulnerabilities
#						In web applications

clear
echo "You are about to remove mod_csrfprotector from APACHE SERVER"
read -p "Are you sure you want to remove it [Y/n]?" yn
if [ "$yn" == "y" ] || [ "$yn" == "Y" ]; then
    echo "Removing mod_csrfprotector" 
	echo "Removing .load file"
	sudo rm /etc/apache2/mods-enabled/csrf_protector.load
	
	echo "Removing .so file"
	sudo rm /usr/lib/apache2/modules/mod_csrfprotector.so
	
	echo "Files removed"
	echo "Restarting apache2.."
	sudo service apache2 restart

else
    echo "Remove process aborted!!"
fi
