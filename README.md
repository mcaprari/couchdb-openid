This is a draft implementation of OpenID version 1.1 for couchdb,
based on http://github.com/etnt/eopenid


   * if user **is not logged in** in and supplies a **new openid**, a new user is created with username=openid.
   * if user **is not logged in** in and supplies a **mapped openid**, user is logged in with mapped user
   * if user **is logged in** and supplies a **new openid**, the openid is added to current user.
   * if user **is logged in** and supplies a **mapped openid**
      * if openid is mapped to the same user, nothing much happens
      * if openid is mapped to a different user, the operation fails 400
   * if user **is logged in AS ADMIN** and supplies a **new openid** the operation fails 500

Quick install:
--------------
   * cd couchdb_install_path/lib/couchdb/erlang/lib/
   * git clone http://github.com/mcaprari/eopenid.git
   * add {couch_httpd_openid_auth, openid_authentication_handler} to local.ini [httpd]/authentication_handlers
  
Quick test:
----------
http://localhost:5984/_session?openid=auth-request&openid-identifier=<your openid>
	

TODO:
----
   * randomize salt on user creation
   * cleanup ets table after auth confirm (or maybe find an alternative to ets tables)
   * reduce dependence from eopenid (dict access routines at least)
   