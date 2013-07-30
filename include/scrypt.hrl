
%% Default Configuration Options

-type scrypt_option() :: {maxtime, number()}
                       | {maxmem, number()}
                       | {maxmemfrac, number()}. %% within range [0,1]

-define(DEFAULT_MAXMEM_BYTES, 1048576).  %% 1 megabyte
-define(DEFAULT_MAXMEMFRAC, 0.125).
-define(DEFAULT_MAXTIME_SEC, 5.0).
-define(DEFAULT_OPTIONS, [ {maxtime, ?DEFAULT_MAXTIME_SEC},
                           {maxmem, ?DEFAULT_MAXMEM_BYTES},
                           {maxmemfrac, ?DEFAULT_MAXMEMFRAC} ]).
