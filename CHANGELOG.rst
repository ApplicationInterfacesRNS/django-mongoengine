=======
0.2.107
=======

* Support for django 1.10, minimum django version: 1.7
* Applied various changes in mongo_auth (from internal patch)
* fixes setup.py, removing trailing comma at end of global __XXX__ variables
* adds missing requirements.txt to manifest
* disable log actions history for admin
* adds missing `has_perms` & `has_usable_password` methods for User document
* adds app_config for all documents & mongo_auth
* adds admin command to clear expired sessions
* adds some custom code & fixes some various internal bugs

