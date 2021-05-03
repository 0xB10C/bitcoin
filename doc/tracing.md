Tracing
=======

To make it possible to have more detailed logging for troubleshooting,
or for keeping track of custom statistics, Bitcoin Core includes 
statically-defined tracepoints. 


The linux kernel can hook into these tracepoints at runtime, but when
disabled they have little to no performance impact. Traces can pass
data which can be processed externally via tools such as `bpftrace` 
and `bcc`.


TODO: are tracepoints included in production releases?


Tracepoint documentation
------------------------

The current tracepoints are listed here.

### net

- `net:process_message(char* addr_str, int node_id, char* msgtype_str, uint8_t* rx_data, size_t rx_size)`

Called for every received P2P message.

- `net:push_message(char* msgtype_str, uint8_t* tx_data, size_t tx_size, int node_id)`

Called for every sent P2P message.

### validation

- `validation:connect_block(int height)`

Called when a new block is connected to the longest chain.




Listing available tracepoints
-----------------------

To list all available probes in Bitcoin Core, use `info probes` in `gdb`:

```
$ gdb src/bitcoind
…
(gdb) info probes
Type Provider   Name            Where              Semaphore Object                                     
stap net        process_message 0x00000000000d48f1           /…/bitcoin/src/bitcoind 
stap net        push_message    0x000000000009db8b           /…/bitcoin/bitcoin/src/bitcoind 
stap validation connect_block   0x00000000002adbe6           /…/bitcoin/bitcoin/src/bitcoind
…
```

Adding tracepoints to Bitcoin Core
------------------

To add a new tracepoint, `#include <util/trace.h>` in the compilation unit where it is to be inserted, then call one of the `TRACEx` macros depending on the number of arguments at the relevant position in the code. Up to 12 arguments can be provided:

```c
#define TRACE(context, event)
#define TRACE1(context, event, a)
#define TRACE2(context, event, a, b)
#define TRACE3(context, event, a, b, c)
#define TRACE4(context, event, a, b, c, d)
#define TRACE5(context, event, a, b, c, d, e)
#define TRACE6(context, event, a, b, c, d, e, f)
#define TRACE7(context, event, a, b, c, d, e, f, g)
#define TRACE8(context, event, a, b, c, d, e, f, g, h)
#define TRACE9(context, event, a, b, c, d, e, f, g, h, i)
#define TRACE10(context, event, a, b, c, d, e, f, g, h, i, j)
#define TRACE11(context, event, a, b, c, d, e, f, g, h, i, j, k)
#define TRACE12(context, event, a, b, c, d, e, f, g, h, i, j, k, l)
```

The `context` and `event` specify the names by which the tracepoint is to be referred to.
Please use `snake_case` and try to make sure that the tracepoint names make sense even
without detailed knowledge of the implementation details. Do not forget to update the
list in this document.

Make sure that the data passed to the tracepoint is inexpensive to compute.
Although the tracepoint itself only has overhead when enabled, the code to
compute arguments is always run — even if the tracepoint is disabled.

For example:

``` C++
TODO: update this
    TRACE5(net, process_message,
           pfrom->addr.ToString().c_str(),
           pfrom->GetId(),
           msg.m_command.c_str(),
           msg.m_recv.data(),
           msg.m_recv.size());
```

TODO: example for time tracking