%%% @author Yew-wei Tan
%%% @copyright (C) 2013, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 13 May 2013 by Yew-wei Tan

-module(scrypt).

-export([init/0, start/0, stop/0]).
-export([hash/1, hash/2]).
-export([verify/2]).

-define(DEFAULT_MAXMEM_MB, 1024).
-define(DEFAULT_MAXMEMFRAC, 0.5).
-define(DEFAULT_MAXTIME_MS, 100).

start() ->
    application:start( ?MODULE ),
    init().

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
    hash( Pass, hash_default_options() ).

hash( Pass, Options ) ->     
    MaxMem = proplists:get_value( maxmem, Options, ?DEFAULT_MAXMEM_MB ),
    MaxMemFrac = proplists:get_value( maxmemfrac, Options, ?DEFAULT_MAXMEMFRAC ),
    MaxTime = proplists:get_value( maxtime, Options, ?DEFAULT_MAXTIME_MS ),
    PassLen = byte_size(Pass),
    hash( Pass, PassLen, MaxMem, MaxMemFrac, MaxTime ).

hash( Pass, PassLen, MaxMem, MaxMemFrac, MaxTime ) ->
    erlang:nif_error( nif_not_loaded ).

hash_default_options() -> 
    [
     {maxmem, ?DEFAULT_MAXMEM_MB},
     {maxmemfrac, ?DEFAULT_MAXMEMFRAC},
     {maxtime, ?DEFAULT_MAXTIME_MS}
    ].

%% @spec verify( Password::binary(), Hash::binary() ) -> boolean().
%% @doc 
verify( Password, Hash ) -> 
    erlang:nif_error( nif_not_loaded ).


init() ->
	%% Start the nifs
	ModPath = filename:dirname(code:which( ?MODULE )),
	So = case code:priv_dir( ?MODULE ) of
			 {error, bad_name} ->
				 filename:join(ModPath, "../priv/", ?MODULE_STRING);
			 Dir ->
				 filename:join(Dir, ?MODULE_STRING)
		 end,

    case erlang:load_nif( So, 0 ) of
        {error, {load_failed, Reason}} ->
            case erlang:system_info( otp_release ) of
                "R15" ++ _ ->
                    Format = ?MODULE_STRING ++ " load NIF failed:~n~p~n",
                    error_logger:warning_msg( Format, [Reason] ),
                    throw({error, Reason});
                _ -> 
                    ok
            end;
        {error, {reload, _}} -> 
            ok;
        ok -> 
            ok;
        Err -> 
            error_logger:warning_msg( "scrypt load error: ~p~n", [Err] ),
            throw({error, Err})
    end,
    
    %% DONE
    {ok, self()}.
