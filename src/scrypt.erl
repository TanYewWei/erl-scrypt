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
-export([encrypt/2, encrypt/3]).
-export([decrypt/2, decrypt/3]).
-export([calibrate/1, current_calibration/0]).

start() ->     
    application:start( ?MODULE ).

stop() -> 
    application:stop( ?MODULE ).


%% @spec hash( Pass::iolist(), Options::list() )
%%           -> {ok, Hash::binary()} | {error,Reason::term()}.
%% 
hash( Pass ) -> 
    hash( Pass, [] ).
hash( Pass, Options ) ->
    scrypt_worker:hash( Pass, Options ).


%% @spec verify( Hash::binary(), Password::binary(), Options::list() ) 
%%             -> boolean().
%% 
%% @doc verifies that a Hash is derived from the given Password using Options
verify( Hash, Pass ) ->
    verify( Hash, Pass, [] ).
verify( Hash, Pass, Options ) ->
    scrypt_worker:verify( Hash, Pass, Options ).


%% @spec encrypt( 
%%         Plaintext::iolist(),
%%         Pass::iolist(),
%%         Options::list()
%%       ) -> {ok, Ciphertext::binary()} | {error, Reason::term()}.
%% 
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
decrypt( Ciphertext, Pass ) -> 
    decrypt( Ciphertext, Pass, [] ).
decrypt( Ciphertext, Pass, Options ) -> 
    scrypt_worker:decrypt( Ciphertext, Pass, Options ).



%% @spec calibrate( Options::list() ) -> ok.
%% 
calibrate( Options ) ->
    scrypt_worker:calibrate( Options ).

%% @spec current_calibration() -> {ok, Options::list()} | {error, Reason::term()}.
%%
current_calibration() -> 
    scrypt_worker:current_calibration().
