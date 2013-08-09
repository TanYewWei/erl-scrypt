erl-scrypt 
==========

erl-scrypt is a simple wrapper around Colin Pervical's [scrypt key derivation function](http://www.tarsnap.com/scrypt.html). 
# Building 

Currently, only a rebar build is supported

```
./rebar compile
```

To use as a dependency, add the following line to your `rebar.config`

```erlang
{deps, [{scrypt, "1.1.1", {git, "https://github.com/TanYewWei/erl-scrypt.git", {tag, "1.1.1"}}}]}
```

As a dependency on elixir projects, add the following tuple to the `deps:` keyword of your `mix.exs`

```elixir
{ :scrypt, github: "TanYewWei/erl-scrypt", tag: "1.1.1" }
```

# Dependencies

The following are required to build the scrypt utility:

* gcc
* make
* libssl-dev

Ubuntu and Debian users can install the dependencies via the command 

```
sudo apt-get install gcc make libssl-dev
```

# Usage

To test from the shell, run the `shell` script. This should give you an erlang prompt with the scrypt application already started.

```erlang
Pass = "some secure password!".
{ok, Hash} = scrypt:hash( Pass ).
true = scrypt:verify( Hash, Pass ).

{ok, Ciphertext} = scrypt:encrypt( "Hello!", "A Strong Password" ).
{ok, Plaintext} = scrypt:decrypt( Ciphertext, "A Strong Password" ).
Plaintext = <<"Hello!">>.

%% With options
Options = [{maxmem, 1024}, {maxmemfrac,0.2}, {maxtime,1.0}].

P0 = "another secure password!".
{ok, H0} = scrypt:hash( P0, Options ).
true = scrypt:verify( H0, P0, Options ).

{ok, C0} = scrypt:encrypt( "Hello Again!", "Another Strong Password", Options ).
{ok, T0} = scrypt:decrypt( C0, "Another Strong Password", Options ).
T0 = <<"Hello Again!">>.
```

Only 4 functions are exported:

```erlang
-spec hash( Pass::iolist(), Options::options() ) -> {ok, Hash::binary()} | {error, Reason::term()}.
-spec verify( Hash::iolist(), Pass::iolist(), Options::options() ) -> boolean().
-spec encrypt( Plaintext::iolist(), Pass::iolist(), Options::options() ) -> {ok, Ciphertext::binary()} | {error, Reason::term()}.
-spec decrypt( Ciphertext::iolist(), Pass::iolist(), Options::options() ) -> {ok, Plaintext::binary()} | {error, Reason::term()}.

-type options() :: [ option_tuple() ].
-type option_tuple() :: {maxmem, integer()} 
                      | {maxmemfrac, float()}
                      | {maxtime, integer()}.
```

The options include:

* `maxmem` - the maximum number of `bytes` of memory to be used in the operation. Any value less than 1 MB (1048576 bytes) will be treated as 1 MB. **Defaults to 1048576**
* `maxmemfrac` - the maximum memory to be used as fraction of total available resources. Any value equal to 0 or greater than 0.5 will result in 0.5 being used. **Defaults to 0.125**
* `maxtime` - the maximum time in `seconds` that the particular operation will take. **Defaults to 5**
