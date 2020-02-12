#ifndef BITCOIN_ZMQ_MCE_H
#define BITCOIN_ZMQ_MCE_H

#include <string>
#include <vector>
#include <zmq/zmqconfig.h>
#include <logging.h>
#include <uint256.h>
#include <zmq.h> // TODO: #if ENABLE_ZMQ <-- place here --> #endif

typedef std::vector<uint8_t> messagepart;

class CZMQMempoolChainEvent
{

    private:
        
        typedef std::vector<uint8_t> messagepart;

        static void send(const std::vector<messagepart>& parts);

        static void* getTraceSocket();

        static messagepart toMessagePart(const uint256 hash);
        
    public:
 
        // TODO: warp function calls in #if ENABLE_ZMQ_MCE <here> #endif
        static void NewBlockHash(const uint256 hash);

};

#endif 