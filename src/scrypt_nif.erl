%%% @author Yew-wei Tan
%%% @copyright (C) 2013, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 13 May 2013 by Yew-wei Tan

-module(scrypt_nif).

-include("scrypt.hrl").

-export([init/0]).
-export([hash_default_options/0]).
-export([hash/2, verify/3]).

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
            error_logger:warning_msg( Format, [Reason] ),
            throw({error, Reason});
        {error, {reload, _}} -> 
            ok;
        ok -> 
            ok;
        Err -> 
            error_logger:warning_msg( "scrypt load error: ~p~n", [Err] ),
            throw({error, Err})
    end.

hash_default_options() -> 
    [
     {maxmem, ?DEFAULT_MAXMEM_BYTES},
     {maxmemfrac, ?DEFAULT_MAXMEMFRAC},
     {maxtime, ?DEFAULT_MAXTIME_SEC}
    ].

hash( Pass, Options ) ->
    MaxMem = proplists:get_value( maxmem, Options, ?DEFAULT_MAXMEM_BYTES ),
    MaxMemFrac = proplists:get_value( maxmemfrac, Options, ?DEFAULT_MAXMEMFRAC ),
    MaxTime = proplists:get_value( maxtime, Options, ?DEFAULT_MAXTIME_SEC ),
    PassBin = iolist_to_binary( Pass ),    
    hash( PassBin, MaxMem, MaxMemFrac, MaxTime ).
hash( Pass, MaxMem, MaxMemFrac, MaxTime ) ->
    erlang:nif_error( nif_not_loaded ).

verify( Pass, Hash, Options ) ->
    MaxMem = proplists:get_value( maxmem, Options, ?DEFAULT_MAXMEM_BYTES ),
    MaxMemFrac = proplists:get_value( maxmemfrac, Options, ?DEFAULT_MAXMEMFRAC ),
    MaxTime = proplists:get_value( maxtime, Options, ?DEFAULT_MAXTIME_SEC ),
    PassBin = iolist_to_binary( Pass ),
    verify( PassBin, Hash, MaxMem, MaxMemFrac, MaxTime ).
verify( Pass, Hash, MaxMem, MaxMemFrac, MaxTime ) ->
    erlang:nif_error( nif_not_loaded ).
