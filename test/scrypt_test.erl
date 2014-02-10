%%% @author Yew-wei Tan
%%% @copyright (C) 2013, Yew-wei Tan
%%% @doc
%%%
%%% @end
%%% Created : 30 May 2013 by Yew-wei Tan

-module(scrypt_test).

-compile(export_all).
-include_lib("eunit/include/eunit.hrl").

hash_and_verify_test_() ->
    {setup,
     fun() -> ok end,
     fun(_) -> ok end,
     [
      {timeout, 60, {"hashing and verifying passwords should work",
       fun() -> 
               %% Hash
               ?debugMsg("Working on Hashing ..."),
               {ok, A0} = scrypt:hash("test password 0"),
               {ok, A1} = scrypt:hash("test password 1",
                                      [ {maxmemfrac, 0.5},
                                        {maxtime, 1.0},
                                        {maxmem, 1024} ]),
               ?debugMsg("Hashing Work Done!"),

               %% Verify
               ?debugMsg("Working on Verification ..."),
               ?assert(scrypt:verify(A0, "test password 0" )),
               ?assert(scrypt:verify(A1, 
                                     "test password 1",
                                     [{maxtime, 1.5}] )),
               ?assert(not scrypt:verify(A0, "test pass 0")),
               ?debugMsg("Verification Done!")
       end}}
     ]}.

encrypt_and_decrypt_test_() -> 
    {setup,
     fun() -> ok end,
     fun(_) -> ok end,
     [
      {timeout, 60, {"encrypting and decrypting passwords should work", 
       fun() -> 
               %% encrypt
               ?debugMsg("Working on Encryption  ..."),
               {ok, A0} = scrypt:encrypt("encrypt me 0!",
                                         "test password 0"),
               {ok, A1} = scrypt:encrypt("encrypt me 1!",
                                         "test password 1",
                                         [ {maxmemfrac, 0.5},
                                           {maxtime, 1.0},
                                           {maxmem, 1024} ]),
               ?debugMsg("Encryption Done!"),

               %% decrypt
               ?debugMsg("Working on Decryption  ..."),
               ?assertEqual({ok, <<"encrypt me 0!">>}, 
                            scrypt:decrypt(A0, "test password 0")),
               ?assertMatch({error, _}, 
                            scrypt:decrypt(A0, "test password 1")),
               ?assertEqual({ok, <<"encrypt me 1!">>}, 
                            scrypt:decrypt(A1, "test password 1")),
               ?assertMatch({error, _},
                            scrypt:decrypt(A1, "test password 0")),
               ?debugMsg("Decryption done!")
       end}}
     ]}.

scrypt_worker_test_() ->
    {inorder,
     [
      {timeout, 60, {"hashing/verification",
       fun() ->
               ?debugMsg("scrypt_worker hashing and verification"),
               {ok, Worker} = create_worker(),
               Pass = <<"test password 0">>,
               {ok, Hash} = scrypt_worker:hash(Worker, Pass),
               ?assert(scrypt_worker:verify(Worker, Hash, Pass))
       end}},

      {timeout, 60, {"encryption/decryption",
       fun() ->
               ?debugMsg("scrypt_worker encryption and decryption"),
               {ok, Worker} = create_worker(),
               
               Plaintext = <<"some plaintext">>,
               Pass = <<"test password 0">>,

               {ok, Ciphertext} = scrypt_worker:encrypt(Worker, Plaintext, Pass),
               ?assertMatch({ok, Plaintext}, scrypt_worker:decrypt(Worker, Ciphertext, Pass))
       end}},

      {"option reconfiguration",
       fun() ->
               ?debugMsg("scrypt_worker dynamic re-configuration"),
               {ok, Worker} = create_worker(),
               
               {ok, O0} = scrypt_worker:get_config(Worker),
               ?assertEqual(O0, default_scrypt_options()),
               
               NewMaxMem = 1000,
               NewConfig = lists:keystore(maxmem, 1, O0, {maxmem, NewMaxMem}),
               {ok, O1} = scrypt_worker:set_config(Worker, NewConfig),

               ?assertEqual(NewMaxMem, proplists:get_value(maxmem, O1)),
               ?assertEqual(proplists:get_value(maxmemfrac, O0),
                            proplists:get_value(maxmemfrac, O1)),
               ?assertEqual(proplists:get_value(maxtime, O0),
                            proplists:get_value(maxtime, O1))
       end}
     ]}.

create_worker() ->
    Config = default_scrypt_options(),
    scrypt_worker:start_link(Config).

default_scrypt_options() ->
    [{maxmem, 4096},
     {maxmemfrac, 0.5},
     {maxtime, 5.0}].
