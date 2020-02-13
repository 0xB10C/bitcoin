#!/usr/bin/env python3
"""Utility functionality for the patched ZMQ interface."""

import struct
import zmq

from test_framework.util import assert_equal

class ZMQSubscriber:
    def __init__(self, socket, topic):
        self.sequence = 0
        self.socket = socket
        self.topic = topic
        self.socket.setsockopt(zmq.SUBSCRIBE, self.topic)

    def receive_multi_payload(self):
        """receives a multipart zmq message with zero, one or multiple payloads
        and checks the topic and sequence number"""
        msg = self.socket.recv_multipart()

        # Message should consist of at least two parts (topic and sequence)
        assert(len(msg) >= 2)
        topic = msg[0]
        sequence = msg[-1]

        # Topic should match the subscriber topic.
        assert_equal(topic, self.topic)
        # Sequence should be incremental.
        assert_equal(struct.unpack('<I', sequence)[-1], self.sequence)
        self.sequence += 1
        return msg[1:-1]
