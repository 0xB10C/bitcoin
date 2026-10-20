P2P and network changes
-----------------------

- A new inbound connection from an address that already connected twice within
  the last 10 to 20 minutes no longer evicts an existing peer when there is no
  room for it, and is dropped instead. This applies both to the overall inbound
  connection limit and to the smaller limit on inbound peers that relay
  transactions (see `-inboundrelaypercent`), so such a connection can still be
  dropped shortly after it sent its `version` message when only the
  transaction-relay limit is reached. Whenever there is room under the
  applicable limit, the connection is accepted as before. This protects
  existing peers from entities that reconnect within seconds of every
  disconnect. Peers with the `noban` permission, connections from local
  addresses and inbound Tor connections are never affected by this.
