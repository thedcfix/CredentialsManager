# Credentials Manager
 Cloud ready tool for managing credentials

Hi, this is tool aimed at working on IBM CloudFoundry and Cloudant for storing credentials about software under development in different environments.
It is based on Python and uses Flask as a web server to run the service. All of the sensitive data are encrypted and authentication is always required to make any action.
If you'r interested in an open source implementation, give a look at how to setup a DB connection using MongoDB. It should be easy to understand how to replace the existing logic.

![Alt text](Figure_1.png?raw=true)

In case you wanted, the application is container-ready and is provided with a Dockerfile to run it without having to configure annoying things. Just remember the containerized version needs to be adjusted to work with MongoDB. Have fun!