-ifndef(_EOPENID_DEBUG).
-define(_EOPENID_DEBUG, true).

-ifdef(debug).
-define(edbg(Fmt,Args), 
		nil).
-else.
-define(edbg(Fmt,Args), true).
-endif.

-endif.
