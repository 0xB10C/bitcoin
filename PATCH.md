# Patch: Mempool and Chain event publishers for ZMQ

This is a patch-set to Bitcoin Core that adds more functionality to the ZMQ interface.
While the patches does not touch consensus or wallet code, it's not recommended to use this node in a consensus critical environment where user
funds are at risk.

## Changes:

### add: multi-payload ZMQ multipart messages

A new internal function overwrite for `zmq_send_multipart()` is added.
This allows us to send ZMQ multipart messages with a variable amount (zero to many) of payload parts.

```
ZMQ multipart message structure
Before: | topic | payload | sequence |
After:  | topic | payload_0 | payload_1 | ... | payload_n | sequence |
```

This change is backward compatible to the format of the existing ZMQ publishers.
The topic is the first part of the message and the sequence is the last part of the message.












