This is a draft implementation of OpenID version 1.1 for couchdb,
based on http://github.com/etnt/eopenid


Quick install:
--------------
   * cd couchdb_install_path/lib/couchdb/erlang/lib/
   * git clone http://github.com/mcaprari/eopenid.git
   * add {couch_httpd_openid_auth, openid_authentication_handler} to local.ini [httpd]/authentication_handlers
  
Quick test:
----------
http://localhost:5984/_session?openid=auth-request&openid-identifier=<your openid>
	
What to expect:
---------------
Only openid is supported and it has only been tested with myopenid.com as openid provider.

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
   * decide if it is wise to map openids to admins (if at all possible)
   * cleanup ets table after auth confirm (or maybe find an alternative to ets tables)
   * reduce dependence from eopenid (dict access routines at least)
   