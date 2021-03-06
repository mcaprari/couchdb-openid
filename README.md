This is a draft implementation of OpenID version 1.1 for couchdb,
based on http://github.com/etnt/eopenid

It seems fairly stable but has only been tested against myopenid.com,
so it is definitely not production ready.

I plan to add support for openid 2.0 and to make couchdb work as openid endpoint.

**The handler code would love to be reviewed by someone with some erlang and couchdb experience**

Demo:
-----
Try the [login page at fortytwo](http://couch.caprazzi.net/fortytwo/_design/fortytwo/_show/auth).

Quick install:
--------------
   * cd couchdb_install_path/lib/couchdb/erlang/lib/
   * git clone git://github.com/mcaprari/couchdb-openid.git
   * cd couchdb-openid
   * make
   * edit local.ini [httpd]/authentication_handlers (or do it form futon) and
	add {couch_httpd_openid_auth, openid_authentication_handler} **BEFORE the default handlers**
   * restart couchdb
  
Quick test:
----------
http://localhost:5984/_session?openid=auth-request&openid-identifier=<your openid>

- optionally add the parameter app-return-address=[an_address_of_your_choice] to be redirected there
when authentication is complete  

What to expect:
---------------
Only openid 1.1 is supported and it has only been tested with myopenid.com as openid provider.

When a client hits the initiation url (above), it is redirected to the openid provider
and prompted to authorise the association. 

Then it's redirected back to the couch and

   * if the client **is not logged in** in and supplies a **new openid**,
a new user is created with username=openid and the client is logged in

   * if the client **is not logged in** in and supplies a **mapped openid**,
the client is logged in as the mapped user

   * if the client **is logged in** and supplies a **new openid**,
	the supplied openid is added to current user, and the client keeps the current login
   * if the client **is logged in** and supplies a **mapped openid**
      * if openid is mapped to the **same user**, the client keeps the current login
      * if openid is mapped to a **different user**, the operation fails 400

   * if user **is logged in AS ADMIN** and supplies a **new openid** the operation fails 500
	

TODO:
----
   * try erl_openid for openid 2.0 support
   * decide if it is wise to map openids to admins (if at all possible)
   * cleanup ets table after auth confirm (or maybe find an alternative to ets tables)
   * reduce dependence from eopenid (dict access routines at least)
   

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/mcaprari/couchdb-openid/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

