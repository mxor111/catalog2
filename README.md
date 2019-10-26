#README File

Item Catalog Project

An Udacity Full Stack Web Developer Nanodegree Project

About:
Develop a web application that provides a list of items within a variety of categories and intergrate third party user registration and authentication.  Authenticated users should have the ability to post, edit, and delete their own items. This project uses persistent data storage to create a RESTful web application that allows users to perform Create, Read, Update, and Delete operations.

The user does not need to be logged in to view the categories or items but will have to create a user id to allow to add categories or new items.

SKILLS / USED

- Python
- HTML
- CSS
- Flask
- sqlalchemy
- OAuth
- Facebook /Google Login

-Proper authentication and authorization checks
-Full CRUD support using sqlalchemy and flask
-JSON endpoints
-Implements OAuth using google an facebook sign-in API

Structure

- README.md
- static folder - styles.css
- template folder  - HTML Files
- itemcatalog.db
- database_setup.py
- fb_client_secrets.json
- client_secrets.json
- LICENSE

APPLICATION NEEDED:

- VAGRANT - https://www.vagrantup.com/
- Udacity Vagrant file  
- VirualBox - https://www.virtualbox.org/wiki/Downloads

USING THE APPLICATION:

1. Download and install Vagrant https://www.vagrantup.com/downloads.html
2. Download and install VirtualBox https://www.virtualbox.org/wiki/Downloads


 - Intall Vagrant and Virtual VirtualBox
 - Clone the Vagrantfile from Repo - https://github.com/mxor111/catalog2
 - Open Terminal / CD in directory
 - Open Terminal and Type: "vagrant up" to run virtual machine
 - After vagrant is installed : Type "vangrant ssh" to login to the VM
 - Type cd/vagrant to navigate to shared repository
 - Down or Close the repository and navigate to it
 - Install or upgrade Flask: from the main directory sudo pip -m install --upgrade flask
 - Set up the database : in Terminal Type:  python database_setup.py
 - Run in Terminal - Type : python application.py
 - Open http://localhost:5000 in your web browser and have Fun!
 - go to http://localhost/catergories to access APPLICATION
 -** you must add a category before adding an items









Created: Michele Novack Abugosh V2. 10/2019
