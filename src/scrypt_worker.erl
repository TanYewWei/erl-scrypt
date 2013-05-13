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

%% API
-export([start_link/0]).
-export([hash/2]).
-export([verify/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE). 

-record(state, {}).

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


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{}}.

handle_call({hash, Pass, Options}, _, State) -> 
    Hash = scrypt_nif:hash( Pass, Options ),
    {reply, {ok,Hash}, State};
handle_call({verify, Pass, Hash, Options}, _, State) -> 
    Verify = scrypt_nif:verify( Pass, Hash, Options ),
    {reply, Verify, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
