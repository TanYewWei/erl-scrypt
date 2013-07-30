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
               {ok,A0} = scrypt:hash( "test password 0" ),
               {ok,A1} = scrypt:hash( "test password 1", 
                                      [ {maxmemfrac, 0.5},
                                        {maxtime, 1.0},
                                        {maxmem, 1024} ]),

               %% Verify                              
               ?assert(scrypt:verify( A0, "test password 0" )),
               ?assert(scrypt:verify( A1, 
                                      "test password 1",
                                      [{maxtime, 2.0}] )),
               ?assert(not scrypt:verify( A0, "test pass 0" ))
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
               {ok,A0} = scrypt:encrypt( "encrypt me 0!", 
                                         "test password 0" ),
               {ok,A1} = scrypt:encrypt( "encrypt me 1!", 
                                         "test password 1", 
                                         [ {maxmemfrac, 0.5},
                                           {maxtime, 1.0},
                                           {maxmem, 1024} ]),
               
               %% decrypt 
               ?assertEqual( {ok,<<"encrypt me 0!">>}, 
                             scrypt:decrypt( A0, "test password 0" )),
               ?assertMatch( {error,_}, 
                             scrypt:decrypt( A0, "test password 1" )),
               ?assertEqual( {ok,<<"encrypt me 1!">>}, 
                             scrypt:decrypt( A1, "test password 1" )),
               ?assertMatch( {error,_}, 
                             scrypt:decrypt( A1, "test password 0" ))
       end}}
     ]}.
