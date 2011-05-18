wire
====

Properly private messaging.
---------------------------

A solution to government-comprimised messaging services, by providing a simple buy powerful user interface to communicate messages and events between activists and groups.

Server Setup
------------

Installation is easiest done with Fabric.

1. Install Fabric with pip.
2. Install supervisor with apt or yum.
3. Set up nginx or another server that fast-cgi forwards to `/tmp/gunicorn_wire.sock`. An example skeleton configuration is here:  
  https://github.com/radiosilence/servers.py/blob/master/skeletons/nginx_wsgi.skel

4. In the project root, run `fab install`. You will need to be able to sudo.
5. When prompted for server, you will likely want to install this machine, so input `localhost`.
5. If necessary, you will be asked for your password in order to sudo. Input it.
6. Will be installed!
