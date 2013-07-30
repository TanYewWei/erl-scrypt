%%% @author Yew-wei Tan
%%% @copyright (C) 2013, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 13 May 2013 by Yew-wei Tan

-module(scrypt).
-include("scrypt.hrl").

-export([start/0, stop/0]).
-export([hash/1, hash/2]).
-export([verify/2, verify/3]).
-export([encrypt/2, encrypt/3]).
-export([decrypt/2, decrypt/3]).

%%%===================================================================
%%% Exported Functions
%%%===================================================================

start() ->
    application:start( scrypt ).

stop() ->
    application:stop( scrypt ).

%% @spec hash( Pass::iolist(), Options::list() )
%%           -> {ok, Hash::binary()} | {error,Reason::term()}.
%% 
hash( Pass ) ->
    hash( Pass, ?DEFAULT_OPTIONS ).
hash( Pass, Options ) ->
    ResolvedOptions = resolve_options( Options ),
    scrypt_nif:hash( Pass, ResolvedOptions ).


%% @spec verify( Hash::binary(), Password::iolist(), Options::list() ) 
%%             -> boolean().
%% 
verify( Hash, Pass ) ->
    verify( Hash, Pass, [] ).
verify( Hash, Pass, Options ) ->
    ResolvedOptions = resolve_options( Options, true ),
    scrypt_nif:verify( Hash, Pass, ResolvedOptions ).


%% @spec encrypt( 
%%         Plaintext::iolist(),
%%         Pass::iolist(),
%%         Options::list()
%%       ) -> {ok, Ciphertext::binary()} | {error, Reason::term()}.
%%
encrypt( Plaintext, Pass ) ->
    encrypt( Plaintext, Pass, [] ).
encrypt( Plaintext, Pass, Options ) ->
    ResolvedOptions = resolve_options( Options ),
    scrypt_nif:encrypt( Plaintext, Pass, ResolvedOptions ).


%% @spec decrypt( 
%%         Ciphertext::iolist(),
%%         Pass::iolist(),
%%         Options::list()
%%       ) -> {ok, Plaintext::binary()} | {error, Reason::term()}.
%%
decrypt( Ciphertext, Pass ) ->
    decrypt( Ciphertext, Pass, [] ).
decrypt( Ciphertext, Pass, Options ) ->
    ResolvedOptions = resolve_options( Options, true ),
    scrypt_nif:decrypt( Ciphertext, Pass, ResolvedOptions ).


%%%-------------------------------------------------------------------
%%% Private
%%%-------------------------------------------------------------------

-spec resolve_options( Options::scrypt_option(),
                       RelaxMaxTime::boolean() ) 
                     -> [ scrypt_option() ].

resolve_options( Options ) ->
    resolve_options( Options, false ).

resolve_options( Options, RelaxMaxTime ) ->
    %% ${RelaxMaxTime} is set to true
    %% during decryption and verification operations.
    %% 
    %% maxtime is intended as a tunable security parameter
    %% during encryption/hashing, while it is treated
    %% as an upper bound during decryption/verification.
    %% 
    %% The tarsnap code will throw an error if it thinks the 
    %% operation will take too long, so there should be little 
    %% danger in setting a higher value for maxtime.
    %% 
    %% However, we still always prefer ${Options} over ${Defaults}
    %% if ${Options} is supplied
    InputMaxTime = proplists:get_value( maxtime, Options, ?DEFAULT_MAXTIME_SEC ),
    MaxTime = case RelaxMaxTime of
                  true -> InputMaxTime * 3;  %% arbitrary multiplier
                  _    -> InputMaxTime
              end,
    R0 = lists:ukeymerge( 1, Options, ?DEFAULT_OPTIONS ),
    R1 = lists:ukeymerge( 1, [{maxtime,MaxTime}], R0 ),
    R1.
