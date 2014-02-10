%%% @author Yew-wei Tan
%%% @copyright (C) 2014, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 10 Feb 2014 by Yew-wei Tan

%% This module is intended to be used as the worker module
%% for any one of the complaint worker pool managers out there.
%%
%% Example code showing the recommended scrypt parameters and how
%% to configure them with poolboy is available in the README
%%
%% So far, this module has been tested with:
%%
%% `poolboy` - https://github.com/devinus/poolboy
%% `pooler` - https://github.com/seth/pooler

-module(scrypt_worker).
-behaviour(gen_server).

-include("scrypt.hrl").

-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).
-export([hash/2, verify/3, encrypt/3, decrypt/3,
         get_config/1, set_config/2]).

-record(state, {maxmem, maxmemfrac, maxtime}).

%% ----------------------------------------------------------------------
%% Public API

hash(Worker, Pass) ->
    gen_server:call(Worker, {hash, Pass}).

verify(Worker, Hash, Pass) ->
    gen_server:call(Worker, {verify, Hash, Pass}).

encrypt(Worker, Plaintext, Pass) ->
    gen_server:call(Worker, {encrypt, Plaintext, Pass}).

decrypt(Worker, Ciphertext, Pass) ->
    gen_server:call(Worker, {decrypt, Ciphertext, Pass}).

get_config(Worker) ->
    gen_server:call(Worker, get_config).

set_config(Worker, Config) ->
    gen_server:call(Worker, {set_config, Config}).

%% ----------------------------------------------------------------------
%% gen_server callbacks

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

init(Args) ->
    MaxMem = proplists:get_value(maxmem, Args, ?DEFAULT_MAXMEM_BYTES),
    MaxMemFrac = proplists:get_value(maxmemfrac, Args, ?DEFAULT_MAXMEMFRAC),
    MaxTime = proplists:get_value(maxtime, Args, ?DEFAULT_MAXTIME_SEC),
    {ok, #state{ maxmem = MaxMem,
                 maxmemfrac = MaxMemFrac,
                 maxtime = MaxTime }}.

handle_call({hash, Pass}, _From, State) ->
    Reply = scrypt_nif:hash(Pass, scrypt_options(State)),
    {reply, Reply, State};

handle_call({verify, Hash, Pass}, _From, State) ->
    Reply = scrypt_nif:verify(Hash, Pass, scrypt_options(State)),
    {reply, Reply, State};

handle_call({encrypt, Plaintext, Pass}, _From, State) ->
    Reply = scrypt_nif:encrypt(Plaintext, Pass, scrypt_options(State)),
    {reply, Reply, State};

handle_call({decrypt, Ciphertext, Pass}, _From, State) ->
    Reply = scrypt_nif:decrypt(Ciphertext, Pass, scrypt_options(State)),
    {reply, Reply, State};

handle_call(get_config, _From, State) ->
    Reply = {ok, [{maxmem, State#state.maxmem},
                  {maxmemfrac, State#state.maxmemfrac},
                  {maxtime, State#state.maxtime}]},
    {reply, Reply, State};

handle_call({set_config, Config}, _From, State) ->
    MaxMem = proplists:get_value(maxmem, Config, State#state.maxmem),
    MaxMemFrac = proplists:get_value(maxmemfrac, Config, State#state.maxmemfrac),
    MaxTime = proplists:get_value(maxtime, Config, State#state.maxtime),
    NewState = State#state{ maxmem = MaxMem,
                            maxmemfrac = MaxMemFrac,
                            maxtime = MaxTime},
    Reply = {ok, [{maxmem, MaxMem},
                  {maxmemfrac, MaxMemFrac},
                  {maxtime, MaxTime}]},
    {reply, Reply, NewState};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ----------------------------------------------------------------------
%% Private Functions

scrypt_options(State) ->
    [{maxmem, State#state.maxmem},
     {maxmemfrac, State#state.maxmemfrac},
     {maxtime, State#state.maxtime}].
