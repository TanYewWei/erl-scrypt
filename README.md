erl-scrypt 
==========

erl-scrypt is a simple wrapper around Colin Pervical's [scrypt key derivation function](http://www.tarsnap.com/scrypt.html). It is very alpha software (it doesn't even have tests yet!), and isn't gauranteed to work.

# Building 

Currently, only a rebar build is supported

```
./rebar compile
```

# Usage

To test from the shell, run the `shell` script. This should give you an erlang prompt with the scrypt application already started.

The only set 

```erlang
Pass = "some secure password!".
{ok, Hash} = scrypt:hash(Pass).
true = scrypt:verify().
```

# Params

There exists a scrypt:hash/2 function and a scrypt:verify/3 function that takes an additional options proplist:

```erlang
-spec hash( Pass::iolist(), Options::options() ) -> {ok, Hash::binary()} | {error, Reason::term()}.
-spec verify( Pass::iolist(), Hash::iolist(), Options::options() ) -> {ok, Hash::binary()} | {error, Reason::term()}.

-type options() :: [ option_tuple() ].
-type option_tuple() :: {maxmem, integer()} 
                      | {maxmemfrac, float()}
                      | {maxtime, integer()}.
```

The options include:

* `maxmem` - the maximum number of `bytes` of memory to be used in the operation. Any value less than 1 MB will be treated as 1 MB. **Defaults to 1024**
* `maxmemfrac` - the maximum memory to be used as fraction of total available resources. Any value equal to 0 or greater than 0.5 will result in 0.5 being used. **Defaults to 0.5**
* `maxtime` - the maximum time in `seconds` that the particular operation will take. **Defaults to 1**
