#include <zmce/zmqmempoolchainevent.h>

static void* pSocketTrace = nullptr;

/* private */

void CZMQMempoolChainEvent::send(const std::vector<messagepart>& parts)
{
    void *sock = getTraceSocket();
    if (!sock) {
        LogPrint(BCLog::ZMQ, "ZMQMempoolChainEvent: error: no sock\n");
        return;
    }

    for (size_t i = 0; i < parts.size(); i++) {
        auto const& part = parts[i];

        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, part.size());
        if (rc != 0) {
            zmqError("ZMQMempoolChainEvent: Unable to initialize ZMQ msg");
            return;
        }

        void* buf = zmq_msg_data(&msg);

        std::memcpy(buf, part.data(), part.size());

        rc = zmq_msg_send(&msg, sock, (i < (parts.size() - 1)) ? ZMQ_SNDMORE : 0);
        if (rc == -1) {
            zmqError("ZMQMempoolChainEvent: Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            return;
        }

        zmq_msg_close(&msg);
    }

    LogPrint(BCLog::ZMQ, "sent message with %d parts\n", parts.size());
}


void* CZMQMempoolChainEvent::getTraceSocket() {
    LogPrint(BCLog::ZMQ, "ZMQMempoolChainEvent: GetTraceSocket()\n");

    if (pSocketTrace) {
        LogPrint(BCLog::ZMQ, "ZMQMempoolChainEvent: returning cached pSocketTrace\n");
        return pSocketTrace;
    }

    const char *address = std::getenv("ZMCE_ADDRESS");
    if (!address) {
        LogPrint(BCLog::ZMQ, "ZMQMempoolChainEvent: ZMCE_ADDRESS not set\n");
        return nullptr;
    }

    LogPrint(BCLog::ZMQ, "ZMQMempoolChainEvent: using address %s\n", address);

    void* pcontext = zmq_ctx_new();
    if (!pcontext) {
        zmqError("ZMQMempoolChainEvent: Unable to initialize context");
        return nullptr;
    }
    
    void * psocket = zmq_socket(pcontext, ZMQ_PUB);
    if (!psocket) {
        zmqError("ZMQMempoolChainEvent: Failed to create socket");
        return nullptr;
    }

    int highWaterMark = 1000;
    int rc = zmq_setsockopt(psocket, ZMQ_SNDHWM, &highWaterMark, sizeof(highWaterMark));
    if (rc != 0) {
        zmqError("ZMQMempoolChainEvent: Failed to set outbound message high water mark");
        zmq_close(psocket);
        return nullptr;
    }

    rc = zmq_bind(psocket, address);
    if (rc != 0) {
        zmqError("ZMQMempoolChainEvent: Failed to bind address");
        zmq_close(psocket);
        return nullptr;
    }

    pSocketTrace = psocket;

    return pSocketTrace;
}

messagepart CZMQMempoolChainEvent::toMessagePart(const uint256 hash){
    messagepart part(hash.begin(), hash.end());
    return part;
}


/* public */

void CZMQMempoolChainEvent::NewBlockHash(const uint256 hash){
    std::vector<messagepart> parts = {
        toMessagePart(hash),
    };
    send(parts);
}