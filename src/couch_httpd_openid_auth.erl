% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License.  You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES77 OR CONDITIONS OF ANY KIND, either express or implied.  See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_httpd_openid_auth).
-include("couch_db.hrl").

-export([openid_authentication_handler/1]).

%	/_session?openid=auth-request&openid-identifier=<identifier> ->
%		user is asking to login with external id and will be redirected to
%		openid endpoint	(should output user_ctx anyway?)
%	/_session?openid=auth-confirm%<openid_protocol> ->
%		endpoint redirected user back here with authentication response		
%		if it's ok install a cookie and return user_ctx
%	/_session ->
%		if cookie is verified, return json user_ctx
%		otherwise return Req (or should add user_ctx to the headers?)
%	any other url ->
%		Req (or should add user_ctx to the headers?)

%% TODO: add no cache!
openid_authentication_handler(#httpd{mochi_req=MochiReq}=Req) ->	
	{Path, _Query, []} = mochiweb_util:urlsplit_path(MochiReq:get(raw_path)),
	case Path of  
		"/_session" ->
			Params = MochiReq:parse_qs(),
			io:format("Request ~p~n", [Params]),
			case proplists:get_value("openid", Params) of								
				"auth-request" ->
					handle_openid_auth_request(Req, Params);				
				"auth-confirm" ->
					handle_openid_auth_confirm(Req, Params);									
				undefined ->
					case verify_openid_cookie(Req) of
						{ok, UserCtx} ->
							couch_httpd:send_json(Req, 200, [], UserCtx);
						_Any ->
							Req
					end
			end;
		_Any ->
			Req			
	end.
	
user_ctx(ClaimedId) ->
	{[
        {ok, true},
    	{name, ?l2b(ClaimedId)},
    	{roles, []},
    	{user_doc, null}
	]}.

verify_openid_cookie(#httpd{mochi_req=MochiReq}=Req) ->
	case MochiReq:get_cookie_value("OpenidAuthSession") of
    	undefined -> none;
    	[] -> none;
    	Cookie ->
    		AssocHandle = couch_util:decodeBase64Url(Cookie),
	    	AssociateDict = get_associate_dict(AssocHandle),
	    	ClaimedId = eopenid_lib:out("openid.claimed_id", AssociateDict),
    		{ok, user_ctx(ClaimedId)}
		end.
	
handle_openid_auth_request(#httpd{mochi_req=MochiReq}=Req, Params) ->
	io:format("AUTH-REQUEST parms: ~p~n", [Params]),
	case proplists:get_value("openid-identifier", Params) of
		undefined ->
			couch_httpd:send_error(Req, 400, [], <<"openid-auth-request">>, <<"with openid=auth-requests MUST provide openid-identifier=identifier">>);
		Identifier ->
			openid_v1_redirect(Req, Identifier)
	end.
		
% http://www.dikappa.net:5984/_session?openid=auth-request&openid-identifier=caprazzi.net	
% http://localhost:5984/_session?openid=auth-request&openid-identifier=caprazzi.net
handle_openid_auth_confirm(#httpd{mochi_req=MochiReq}=Req, Params) ->
	io:format("AUTH-CONFIRM parms: ~p~n", [Params]),
	case proplists:get_value("openid.assoc_handle", Params) of
		undefined ->
			couch_httpd:send_error(Req, 400, [], <<"openid-auth-confirm">>, <<"with openid=auth-confirm MUST provide openid.assoc_handle">>);
		AssocHandle ->
			AssociateDict = get_associate_dict(AssocHandle),
			case eopenid_v1:verify_signed_keys(MochiReq:get(raw_path), AssociateDict) of
				true ->
					io:format("Verified ~p~n", [AssociateDict]),
					% create user
					OpenId = eopenid_lib:out("openid.claimed_id", AssociateDict),
					Created = create_or_update_user_doc(OpenId),
					io:format("Created doc: ~p~n",[Created]),
					Cookie = cookie_auth(Req, AssocHandle),						
					couch_httpd:send_json(Req, 200, [Cookie], user_ctx(OpenId));
				false ->
					io:format("Not Verified ~p~n", [AssociateDict]),
					boom
			end
	end.

cache_busting_headers() ->
	[
        {"Date", httpd_util:rfc1123_date()},
        {"Cache-Control", "no-cache"},
        % Past date, ON PURPOSE!
        {"Expires", "Fri, 01 Jan 1990 00:00:00 GMT"},
        {"Pragma", "no-cache"}
	].

create_or_update_user_doc(OpenId) ->
	DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
	{ok, Db} = couch_db:open(DbName, [{user_ctx, #user_ctx{roles=[<<"_admin">>]}}]),
	Doc = create_user_doc(OpenId),
	couch_db:update_doc(Db, Doc, [full_commit]).
	
create_user_doc(OpenId) ->
	DocId = ?l2b("org.couchdb.user:" ++ OpenId),
	couch_doc:from_json_obj({[
		{<<"_id">>, DocId},
		{<<"type">>,<<"user">>},
		{<<"username">>, ?l2b(OpenId)},
		{<<"roles">>, []},
		{<<"openid">>,[?l2b(OpenId)]}
	]})
	
	.
	
cookie_auth(#httpd{mochi_req=MochiReq}=Req, AssocHandle) ->	
	mochiweb_cookies:cookie("OpenidAuthSession", couch_util:encodeBase64Url(AssocHandle), [{path, "/"}, {http_only, true}]).
		
openid_v1_redirect(Req, Identifier) ->
	application:start(eopenid),
	
	Conf = eopenid_lib:foldf(
		[eopenid_lib:in("openid.return_to", couch_httpd:absolute_uri(Req, "/_session?openid=auth-confirm")),
		eopenid_lib:in("openid.trust_root", couch_httpd:absolute_uri(Req, "/"))
	], eopenid_lib:new()),
	{ok, Discover} = eopenid_v1:discover(Identifier, Conf),
	{ok, Associate} = eopenid_v1:associate(Discover),
	{ok, Url} = eopenid_v1:checkid_setup(Associate),
	ok = store_associate_dict(Associate),
	io:format("Identifier: ~p~nDiscover: ~p~nAssociate: ~p~n Url: ~p~n",[Identifier, Discover, Associate, Url]),
	Headers = [{"Location", Url}] ++ cache_busting_headers(),
	couch_httpd:send_response(Req, 301, Headers, <<>>).

store_associate_dict(Associate) ->
	Handle = proplists:get_value("openid.assoc_handle", Associate),
	io:format("storing ~p for ~p~n", [Handle, Associate]),
	true = ets:insert(ets_maybe_new(openid_associations),
		{{assoc_handle, Handle}, Associate}),
	ok.

get_associate_dict(AssocHandle) ->
	Key = {assoc_handle, AssocHandle},
	[{Key, AssociateDict}] = ets:lookup(openid_associations, Key),
	AssociateDict.

ets_maybe_new(Table) ->
	case ets:info(Table) of
		undefined ->
			ets:new(Table, [set, named_table]);
		Info ->
			Table
	end.