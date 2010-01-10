% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License.  You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_httpd_openid_auth).
-include("couch_db.hrl").

-export([openid_authentication_handler/1]).

% Step-1 The user declares he owns an openId identifier
% Short of better ideas, I check the request contains the field 'openid-identifier'
% http://localhost:5984/?openid-identifier=http://caprazzi.net
% http://localhost:5984/?openid-return&openid.assoc_handle={HMAC-SHA1}{4b49f90f}{69JPbA%3D%3D}&openid.identity=http%3A%2F%2Fcaprazzi.net%2Fposts%2Fauthor%2Fadmin%2F&openid.mode=id_res&openid.response_nonce=2010-01-10T15%3A59%3A28Z5J5tOM&openid.return_to=http%3A%2F%2Flocalhost%3A5984%3Fopenid-return&openid.sig=IinulkrUobwEFh3GK7ulMzxC67Y%3D&openid.signed=assoc_handle%2Cidentity%2Cmode%2Cresponse_nonce%2Creturn_to%2Csigned

openid_authentication_handler(#httpd{mochi_req=MochiReq}=Req) ->
	{Path, _Query, []} = mochiweb_util:urlsplit_path(MochiReq:get(raw_path)),
	case Path of  
		"/_session" ->
			Params = MochiReq:parse_qs(),
			case proplists:get_value("openid", Params) of
				undefined ->
					Req;
				AuthStage ->
					ets:new(openid_associations, [set, named_table]),
					handle_openid_request(AuthStage, Req, Params)
			end;
		_Any ->
			Req
	end.
	
handle_openid_request("auth-request", Req, Params) ->
	io:format("AUTH-REQUEST~n"),
	case proplists:get_value("openid-identifier", Params) of
		undefined ->
			boom;
		Identifier ->
			openid_v1_redirect(Req, Identifier)
	end;
	
handle_openid_request("auth-confirm", Req, Params) ->
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
		[eopenid_lib:in("openid.return_to", "http://localhost:5984/_session?openid=auth-confirm"),
		eopenid_lib:in("openid.trust_root", "http://localhost:5984")
	], eopenid_lib:new()),
	{ok, Discover} = eopenid_v1:discover(Identifier, Conf),
	{ok, Associate} = eopenid_v1:associate(Discover),
	{ok, Url} = eopenid_v1:checkid_setup(Associate),
	ok = store_associate_dict(Associate),
	io:format("Identifier: ~p~nDiscover: ~p~nAssociate: ~p~n Url: ~p~n",[Identifier, Discover, Associate, Url]),
	Headers = [{"Location", Url}],
	couch_httpd:send_response(Req, 301, Headers, <<>>).

store_associate_dict(Associate) ->
	true = ets:insert(openid_associations, {proplists:get_value("openid.assoc_handle", Associate), Associate}),
	ok.