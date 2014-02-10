%%% @author Yew-wei Tan
%%% @copyright (C) 2013, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 13 May 2013 by Yew-wei Tan

-module(scrypt_nif).

-include("scrypt.hrl").

-export([init/0]).
-export([hash/2, verify/3]).
-export([encrypt/3, decrypt/3]).

-on_load(init/0).

init() ->
	%% Start the nifs
    App = scrypt,
	ModPath = filename:dirname(code:which( App )),
	So = case code:priv_dir( App ) of
			 {error, bad_name} ->
				 filename:join([ModPath, "../priv/", ?MODULE_STRING]);
			 Dir ->
				 filename:join(Dir, ?MODULE_STRING)
		 end,
    case erlang:load_nif( So, 0 ) of
        {error, {load_failed, Reason}} ->
            Format = ?MODULE_STRING ++ " load NIF failed:~n~p~n",
            error_logger:warning_msg(Format, [Reason]),
            throw({error, Reason});
        {error, {reload, _}} ->
            ok;
        ok ->
            ok;
        Err ->
            error_logger:warning_msg( "scrypt load error: ~p~n", [Err] ),
            throw({error, Err})
    end.


%% @spec hash(Pass::iolist(), Options::list())
%%           -> {ok, Hash::binary()} | {error,Reason::term()}.
%%
hash(Pass, Options) ->
    {MaxMem, MaxMemFrac, MaxTime} = get_options_tuple(Options),
    hash(iolist_to_binary(Pass), 
         MaxMem, 
         float(MaxMemFrac), 
         float(MaxTime)).

hash(_Pass, _MaxMem, _MaxMemFrac, _MaxTime) ->
    erlang:nif_error(nif_not_loaded).


%% @spec verify(Hash::iolist(), Password::iolist(), Options::list())
%%             -> boolean().
%%
verify(Hash, Pass, Options) ->
    {MaxMem, MaxMemFrac, MaxTime} = get_options_tuple(Options),
    verify(iolist_to_binary(Pass), 
           MaxMem,
           float(MaxMemFrac), 
           float(MaxTime),
           iolist_to_binary(Hash)).

verify(_Pass, _MaxMem, _MaxMemFrac, _MaxTime, _Hash) ->
    erlang:nif_error(nif_not_loaded).

%% @spec encrypt( 
%%         Plaintext::iolist(),
%%         Pass::iolist(),
%%         Options::list()
%%       ) -> {ok, Ciphertext::binary()} | {error, Reason::term()}.
%% 
encrypt(Plaintext, Pass, Options) -> 
    {MaxMem, MaxMemFrac, MaxTime} = get_options_tuple(Options),
    encrypt(iolist_to_binary(Pass),
            MaxMem,
            float(MaxMemFrac),
            float(MaxTime),
            iolist_to_binary(Plaintext)).

encrypt(_Pass, _MaxMem, _MaxMemFrac, _MaxTime, _Plaintext) -> 
    erlang:nif_error(nif_not_loaded).

%% @spec decrypt( 
%%         Ciphertext::iolist(),
%%         Pass::iolist(),
%%         Options::list()
%%       ) -> {ok, Plaintext::binary()} | {error, Reason::term()}.
%%
decrypt(Ciphertext, Pass, Options) -> 
    {MaxMem, MaxMemFrac, MaxTime} = get_options_tuple(Options),
    decrypt(iolist_to_binary(Pass),
            MaxMem,
            float(MaxMemFrac), 
            float(MaxTime), 
            iolist_to_binary(Ciphertext)).

decrypt(_Pass, _MaxMem, _MaxMemFrac, _MaxTime, _Ciphertext) -> 
    erlang:nif_error(nif_not_loaded).


%% ----------------------------------------------------------------------
%% PRIVATE
%% ----------------------------------------------------------------------

get_options_tuple(Options) ->
    MaxMem = proplists:get_value(maxmem, Options, ?DEFAULT_MAXMEM_BYTES),
    MaxMemFrac = proplists:get_value(maxmemfrac, Options, ?DEFAULT_MAXMEMFRAC),
    MaxTime = proplists:get_value(maxtime, Options, ?DEFAULT_MAXTIME_SEC),
    {MaxMem, MaxMemFrac, MaxTime}.
