%%%-------------------------------------------------------------------
%%% @author Yew-wei Tan
%%% @copyright (C) 2013, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 13 May 2013 by Yew-wei Tan
%%%-------------------------------------------------------------------
-module(scrypt_worker).

-behaviour(gen_server).
-include("scrypt.hrl").

%% API
-export([start_link/0]).
-export([hash/2, verify/3]).
-export([calibrate/1]).
-export([encrypt/3, decrypt/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, { maxmem = ?DEFAULT_MAXMEM_BYTES,
                 maxmemfrac = ?DEFAULT_MAXMEMFRAC,
                 maxtime = ?DEFAULT_MAXTIME_SEC
               }).

%%%===================================================================
%%% API
%%%===================================================================

start_link() -> 
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

hash( Pass, Options ) -> 
    Call = {hash, Pass, Options},
    gen_server:call( ?MODULE, Call, infinity ).

verify( Pass, Hash, Options ) -> 
    Call = {verify, Pass, Hash, Options},
    gen_server:call( ?MODULE, Call, infinity ).

calibrate( Options ) ->
    Cast = {calibrate, Options},
    gen_server:cast( ?MODULE, Cast ).

encrypt( Plaintext, Pass, Options ) ->
    Call = {encrypt, Plaintext, Pass, Options},
    gen_server:call( ?MODULE, Call, infinity ).

decrypt( Ciphertext, Pass, Options ) ->
    Call = {decrypt, Ciphertext, Pass, Options},
    gen_server:call( ?MODULE, Call, infinity ).


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{}}.

handle_call({hash, Pass, Options}, _, State) ->
    Resolved_Options = resolve_options( Options, State ),
    Hash = scrypt_nif:hash( Pass, Resolved_Options ),
    {reply, {ok,Hash}, State};

handle_call({verify, Pass, Hash, Options}, _, State) -> 
    Resolved_Options = resolve_options( Options, State, true ),
    Verify = scrypt_nif:verify( Pass, Hash, Resolved_Options ),
    {reply, Verify, State};

handle_call({encrypt, Plaintext, Pass, Options}, _, State) -> 
    Resolved_Options = resolve_options( Options, State ),
    Ciphertext = scrypt_nif:encrypt( Plaintext, Pass, Resolved_Options ),
    {reply, {ok,Ciphertext}, State};

handle_call({decrypt, Ciphertext, Pass, Options}, _, State) ->
    Resolved_Options = resolve_options( Options, State, true ),
    Plaintext = scrypt_nif:decrypt( Ciphertext, Pass, Resolved_Options ),
    {reply, {ok,Plaintext}, State};

handle_call(_, _, State) ->
    {reply, ok, State}.

handle_cast({calibrate, Options}, State) ->
    Resolved = resolve_options( Options, State ),
    MaxMem = proplists:get_value( maxmem, Resolved ),
    MaxMemFrac = proplists:get_value( maxmemfrac, Resolved ),
    MaxTime = proplists:get_value( maxtime, Resolved ),
    NewState = State#state{ maxmem = MaxMem, 
                            maxmemfrac = MaxMemFrac,
                            maxtime = MaxTime },
    {noreply, NewState};

handle_cast(_, State) ->
    {noreply, State}.

handle_info(_, State) ->
    {noreply, State}.

terminate(_, _) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec resolve_options( Options::scrypt_option(), 
                       State::term(), 
                       RelaxMaxTime::boolean() ) 
                     -> [ scrypt_option() ]. 

resolve_options( Options, State ) -> 
    resolve_options( Options, State, false ).
resolve_options( Options, State, RelaxMaxTime ) ->
    %% ${RelaxMaxTime} is set to true
    %% during decryption and verification operations.
    %% 
    %% Note that maxtime is intended as a tunable security parameter
    %% during encryption/hashing, while it is treated as an upper bound
    %% during decryption/verification.
    %% 
    %% The tarsnap code will throw an error if it thinks the 
    %% operation will take too long, so there should be little 
    %% danger in setting a higher value for maxtime.
    %% 
    %% However, we still always prefer ${Options} over ${Defaults}
    %% if ${Options} is supplied
    Defaults = get_options( State, RelaxMaxTime ),
    lists:ukeymerge( 1, Options, Defaults ). 

get_options( State, RelaxMaxTime ) ->
    #state{ maxmem=Maxmem,
            maxmemfrac=MaxmemFrac,
            maxtime=MaxTime
          } = State,
    [
     {maxmem, Maxmem}, 
     {maxmemfrac, MaxmemFrac},
     {maxtime, case RelaxMaxTime of 
                   true -> MaxTime * 3; %% arbitrary value
                   _    -> MaxTime
               end}
    ].
