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

openid_authentication_handler(#httpd{mochi_req=MochiReq}=Req) ->	
	{Path, _Query, []} = mochiweb_util:urlsplit_path(MochiReq:get(raw_path)),
	case Path of  
		"/_session" ->
			Params = MochiReq:parse_qs(),
			case proplists:get_value("openid", Params) of								
				"auth-request" ->
					handle_openid_auth_request(Req, Params);				
				"auth-confirm" ->
					handle_openid_auth_confirm(Req, Params);									
				undefined ->
					Req
			end;
		_Any ->
			Req			
	end.

user_ctx(ClaimedId, UserDoc) ->
	{[
        {ok, true},
    	{name, ?l2b(ClaimedId)},
    	{roles, []},
		{salt, ?l2b("salt")},
    	{user_doc, couch_doc:to_json_obj(UserDoc,[])}
	]}.
	
handle_openid_auth_request(Req, Params) ->
	case proplists:get_value("openid-identifier", Params) of
		undefined ->
			couch_httpd:send_error(Req, 400, [], <<"openid-auth-request">>, <<"with openid=auth-requests MUST provide openid-identifier=identifier">>);
		Identifier ->
			openid_v1_redirect(Req, Identifier)
	end.
		
% http://www.dikappa.net:5984/_session?openid=auth-request&openid-identifier=caprazzi.net	
% http://localhost:5984/_session?openid=auth-request&openid-identifier=caprazzi.net

handle_openid_auth_confirm(#httpd{mochi_req=MochiReq}=Req, Params) ->
	case proplists:get_value("openid.assoc_handle", Params) of
		undefined ->
			couch_httpd:send_error(Req, 400, [], <<"openid-auth-confirm">>, <<"with openid=auth-confirm MUST provide openid.assoc_handle">>);
		AssocHandle ->
			AssociateDict = get_associate_dict(AssocHandle),
			case eopenid_v1:verify_signed_keys(MochiReq:get(raw_path), AssociateDict) of
				true ->
					OpenId = eopenid_lib:out("openid.claimed_id", AssociateDict),
					{ok, UserDoc} = get_or_create_user_doc(OpenId),
					Secret = couch_config:get("couch_httpd_auth", "secret"),
					FullSecret = ?l2b(Secret ++ "salt"),
					Rq = Req#httpd{user_ctx=#user_ctx{name=?l2b(OpenId)}, auth={FullSecret, true}}, 
					Cookie = couch_httpd_auth:cookie_auth_header(Rq, []),
					couch_httpd:send_json(Rq, 200, Cookie, user_ctx(OpenId, UserDoc));
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

get_or_create_user_doc(OpenId) ->
	DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
	{ok, Db} = couch_db:open(DbName, [{user_ctx, #user_ctx{roles=[<<"_admin">>]}}]),
	case find_user_by_openid(Db, OpenId) of
		not_found ->
			%% not found, create 
			Doc = create_user_doc(OpenId),
			couch_db:update_doc(Db, Doc, [full_commit]),
			{ok, Doc};
		{ok, Doc} ->
			{ok, Doc}
	end.

find_user_by_openid(Db, OpenId) ->
	% DesignId = <<"_design/_openid">>,
	% ViewName = <<"users_by_openids">>
	% Stale = nil,
	% {ok, View, Group}  = couch_view:get_map_view(Db, DesignId, ViewName, nil),
	%% ... magic happens ... and a user doc is returned
	%% ... or not
	% create_user_doc(OpenId).
	DocId = ?l2b("org.couchdb.user:" ++ OpenId),
	case couch_db:open_doc(Db, DocId) of
		{ok, Doc} ->
			{ok, Doc};
		_Else ->
			not_found
	end.

create_user_doc(OpenId) ->
	DocId = ?l2b("org.couchdb.user:" ++ OpenId),
	couch_doc:from_json_obj({[
		{<<"_id">>, DocId},
		{<<"type">>,<<"user">>},
		{<<"username">>, ?l2b(OpenId)},
		{<<"salt">>, ?l2b("salt")},
		{<<"roles">>, []},
		{<<"openid">>,[?l2b(OpenId)]}
	]}).
			
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
	Headers = [{"Location", Url}] ++ cache_busting_headers(),
	couch_httpd:send_response(Req, 301, Headers, <<>>).

store_associate_dict(Associate) ->
	Handle = proplists:get_value("openid.assoc_handle", Associate),
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
		_Info ->
			Table
	end.