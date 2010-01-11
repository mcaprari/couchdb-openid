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
				undefined ->
					Req;
				"auth-request" ->
					handle_openid_auth_request(Req, Params);
				"auth-confirm" ->
					handle_openid_auth_confirm(Req, Params)
			end;
		_Any ->
			Req
	end.
	
handle_openid_auth_request(#httpd{mochi_req=MochiReq}=Req, Params) ->
	case proplists:get_value("openid-identifier", Params) of
		undefined ->
			boom;
		Identifier ->
			openid_v1_redirect(Req, Identifier)
		end.
	
handle_openid_auth_confirm(Req, Params) ->
	io:format("AUTH-CONFIRM parms: ~p~n", [Params]),
	case proplists:get_value("openid-identifier", Params) of
		undefined ->
			%% MUST have openid-identifer
			boom;
		Identifier ->
			openid_v1_redirect(Req, Identifier)
	end.
		
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
	Headers = [{"Location", Url}],
	couch_httpd:send_response(Req, 301, Headers, <<>>).

store_associate_dict(Associate) ->
	true = ets:insert(ets_maybe_new(openid_associations),
		{proplists:get_value("openid.assoc_handle", Associate), Associate}),
	ok.

ets_maybe_new(Table) ->
	case ets:info(Table) of
		undefined ->
			ets:new(Table, [set, named_table]);
		Info ->
			Table
	end.