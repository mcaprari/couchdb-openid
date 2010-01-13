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
%
% Matteo Caprari <matteo.caprari@gmail.com> - Jan 2010
-module(couch_httpd_openid_auth).
-include("couch_db.hrl").

-export([openid_authentication_handler/1]).

openid_authentication_handler(#httpd{mochi_req=MochiReq}=Req) ->    
	io:format("openid-authentication-handler~n"),
    {Path, _Query, []} = mochiweb_util:urlsplit_path(MochiReq:get(raw_path)),
    case Path of  
        "/_session" ->
            Params = MochiReq:parse_qs(),
            case proplists:get_value("openid", Params) of
                "auth-request" -> handle_openid_auth_request(Req, Params);
                "auth-confirm" -> handle_openid_auth_confirm(Req, Params);
                undefined ->
                    Req
            end;
        _Any ->
            Req         
    end.
    
handle_openid_auth_request(Req, Params) ->
    case proplists:get_value("openid-identifier", Params) of
        undefined ->
            couch_httpd:send_error(Req, 400, [],
				<<"openid-auth-request">>,
				<<"with openid=auth-requests MUST provide openid-identifier=identifier">>);
        Identifier ->
            openid_v1_redirect(Req, Identifier)
    end.
        
handle_openid_auth_confirm(#httpd{mochi_req=MochiReq}=Req, Params) ->
    case proplists:get_value("openid.assoc_handle", Params) of
        undefined ->
            couch_httpd:send_error(Req, 400, [],
				<<"openid-auth-confirm">>,
				<<"with openid=auth-confirm MUST provide openid.assoc_handle">>);
        AssocHandle ->
            AssociateDict = get_associate_dict(AssocHandle),
            case eopenid_v1:verify_signed_keys(MochiReq:get(raw_path), AssociateDict) of
				false ->
                    couch_httpd:send_error(Req, 400,
						<<"openid-auth-confirm">>, 
						<<"signed keys not verified">>);
                true ->
                    OpenId = eopenid_lib:out("openid.claimed_id", AssociateDict),
                    {ok, UserDoc} = ensure_user_doc_exists(OpenId),
                    Secret = ?l2b(couch_config:get("couch_httpd_auth", "secret")),
					{UserProps} = (UserDoc)#doc.body,
					UserSalt = proplists:get_value(<<"salt">>, UserProps, <<"">>),
					Username = proplists:get_value(<<"username">>, UserProps),
					couch_httpd_auth:handle_session_req(Req#httpd{
						user_ctx=#user_ctx{name=Username},
						auth={<<Secret/binary, UserSalt/binary>>, true}}
					)
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

ensure_user_doc_exists(OpenId) ->
    DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
    {ok, Db} = couch_httpd_auth:ensure_users_db_exists(DbName),
    DesignId = <<"_design/_openid">>,
    ok = ensure_openid_ddoc_exists(Db, DesignId),
    case find_user_by_openid(Db, DesignId, OpenId) of
        user_not_found ->
            Doc = create_user_doc(OpenId),
            couch_db:update_doc(Db, Doc, [full_commit]),
            {ok, Doc};
        {ok, Doc} ->
			{UserProps} = (Doc)#doc.body,
			MappedIds = proplists:get_value(<<"openid">>, UserProps),
			case lists:any(fun(El) -> El == ?l2b(OpenId) end, MappedIds) of
				true ->
					{ok, Doc};
				false ->
					P = proplists:delete(<<"openid">>, UserProps) ++ [?l2b(OpenId)],
					{ok, Updated} = couch_db:update_doc(Db, Doc#doc{body=P}, [full_commit]),
					io:format("Updated: ~p~n", [Updated]),
					{ok, Updated}
			end
    end.

find_user_by_openid(Db, DesignId, OpenId) ->
    ViewName = <<"users_by_openid">>,
    {ok, View, _Group} = couch_view:get_map_view(Db, DesignId, ViewName, _Stale=nil),
    FoldFun = fun({{_, UserDocId}, _}, _, _) -> {stop, UserDocId} end,
    Keys = [{start_key, {?l2b(OpenId), ?MIN_STR}},
            {end_key, {?l2b(OpenId), ?MAX_STR}}],
    case couch_view:fold(View, FoldFun, {user_not_found}, Keys) of
        {ok, _, {user_not_found}} ->
            user_not_found;
        {ok, _, UserDocId} ->
            {ok, Doc} = couch_db:open_doc(Db, UserDocId),
            {ok, Doc}
    end.

ensure_openid_ddoc_exists(Db, DDocId) -> 
    try couch_httpd_db:couch_doc_open(Db, DDocId, nil, []) of
        _Foo ->
            ok
    catch 
        _:_Error -> 
            % create the design document
            {ok, AuthDesign} = openid_design_doc(DDocId),
            {ok, _Rev} = couch_db:update_doc(Db, AuthDesign, []),
            ok
    end.
    
openid_design_doc(DocId) ->
    DocProps = [
        {<<"_id">>, DocId},
        {<<"language">>,<<"javascript">>},
        {<<"views">>, {[
            {<<"users_by_openid">>,
                {[
                    {
                        <<"map">>,
                        <<"function(doc) {
                            if (doc.type === 'user' && doc.openid) {
                                doc.openid.forEach(function(openid) {
                                    emit(openid, doc.username);
                                });
                            }
                        }">>
                    }
                ]}
            }
        ]}}
    ],
    {ok, couch_doc:from_json_obj({DocProps})}.

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