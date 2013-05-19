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
-export([calibrate/1]).
-export([encrypt/2, encrypt/3]).
-export([decrypt/2, decrypt/3]).

start() ->     
    application:start( ?MODULE ).

stop() -> 
    application:stop( ?MODULE ).


%% @spec hash( Pass::iolist(), Options::list() )
%%           -> {ok, Hash::binary()} | {error,Reason::term()}.
%% 
%% @doc
hash( Pass ) -> 
    hash( Pass, [] ).
hash( Pass, Options ) ->
    scrypt_worker:hash( Pass, Options ).


%% @spec verify( Password::binary(), Hash::binary(), Options::list() ) 
%%             -> boolean().
%% 
%% @doc verifies that a Hash is derived from the given Password using Options
verify( Pass, Hash ) ->
    verify( Pass, Hash, [] ).
verify( Pass, Hash, Options ) ->
    scrypt_worker:verify( Pass, Hash, Options ).


%% @spec calibrate( Options::list() ) -> ok | {error, Reason::term()}.
%% 
%% @doc
calibrate( Options ) ->
    scrypt_worker:calibrate( Options ).


%% @spec encrypt( 
%%         Plaintext::iolist(),
%%         Pass::iolist(),
%%         Options::list()
%%       ) -> {ok, Ciphertext::binary()} | {error, Reason::term()}.
%% 
%% @doc
encrypt( Plaintext, Pass ) ->
    encrypt( Plaintext, Pass, [] ).
encrypt( Plaintext, Pass, Options ) -> 
    scrypt_worker:encrypt( Plaintext, Pass, Options ).


%% @spec decrypt( 
%%         Ciphertext::iolist(),
%%         Pass::iolist(),
%%         Options::list()
%%       ) -> {ok, Plaintext::binary()} | {error, Reason::term()}.
%% 
%% @doc
decrypt( Ciphertext, Pass ) -> 
    decrypt( Ciphertext, Pass, [] ).
decrypt( Ciphertext, Pass, Options ) -> 
    scrypt_worker:decrypt( Ciphertext, Pass, Options ).
