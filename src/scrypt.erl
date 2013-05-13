%%% @author Yew-wei Tan
%%% @copyright (C) 2013, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 13 May 2013 by Yew-wei Tan

-module(scrypt).

-export([start/0, stop/0]).
-export([hash/1, hash/2]).
-export([verify/2, verify/3]).

start() ->     
    application:start( ?MODULE ).

stop() -> 
    application:stop( ?MODULE ).

%% @spec hash( 
%%         Subject::iolist(), 
%%         Salt::iolist(), 
%%         Options::list()
%%       ) -> {ok, Hash::binary()} | {error,Reason::term()}.
%% 
%% @doc 
hash( Pass ) -> 
    hash( Pass, [] ).
hash( Pass, Options ) ->
    scrypt_worker:hash( Pass, Options ).

%% @spec verify( Password::binary(), Hash::binary() ) -> boolean().
%% @doc 
verify( Pass, Hash ) ->
    verify( Pass, Hash, [] ).
verify( Pass, Hash, Options ) ->
    scrypt_worker:verify( Pass, Hash, Options ).
