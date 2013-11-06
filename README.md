Dynamic DNS service using PowerDNS
==================================

These are a number of convenience scripts to run a dynamic DNS service with PowerDNS.

www/update.php
--------------
A PHP script you can deploy on your webserver. Routers can hit the script with:

* a GET parameter ``hostname=...`` containing the host name they want to update
* HTTP auth credentials

The IP address is read from the web server. If that does not work for you, make sure the router passes in the IP address and adjust the script to handle that.

*Note:* This is based on an article published in German IT magazine c't in November 2013. Thanks to the authors Mirko Dölle, Thomas Koch, Peter Siering.

