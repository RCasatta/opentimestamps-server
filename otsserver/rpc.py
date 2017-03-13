# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Server.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Server including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import binascii
import http.server
import socketserver
import json
import logging
import bitcoin.core

from opentimestamps.core.serialize import StreamSerializationContext


class RPCRequestHandler(http.server.BaseHTTPRequestHandler):
    MAX_DIGEST_LENGTH = 64
    """Largest digest that can be POSTed for timestamping"""

    NONCE_LENGTH = 16
    """Length of nonce added to submitted digests"""

    digest_queue = None

    def post_digest(self):
        content_length = int(self.headers['Content-Length'])

        if content_length > self.MAX_DIGEST_LENGTH:
            self.send_response(400)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'digest too long')
            return

        digest = self.rfile.read(content_length)

        timestamp = self.aggregator.submit(digest)

        self.send_response(200)
        self.send_header('Content-type', 'application/octet-stream')
        self.end_headers()

        ctx = StreamSerializationContext(self.wfile)
        timestamp.serialize(ctx)

    def get_timestamp(self):
        commitment = self.path[len('/timestamp/'):]

        try:
            commitment = binascii.unhexlify(commitment)
        except binascii.Error:
            self.send_response(400)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Cache-Control', 'public, max-age=31536000') # this will never not be an error!
            self.end_headers()
            self.wfile.write(b'commitment must be hex-encoded bytes')
            return

        try:
            timestamp = self.calendar[commitment]
        except KeyError:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')

            # Pending?
            reason = self.calendar.stamper.is_pending(commitment)
            if reason:
                reason = reason.encode()

                # The commitment is pending, so its status will change soonish
                # as blocks are found.
                self.send_header('Cache-Control', 'public, max-age=60')

            else:
                # The commitment isn't in this calendar at all. Clients only
                # get specific commitments from servers, so in the current
                # implementation there's no reason why this response would ever
                # change.
                self.send_header('Cache-Control', 'public, max-age=3600')
                reason = b'Not found'

            self.end_headers()
            self.wfile.write(reason)
            return

        self.send_response(200)

        # Since only Bitcoin attestations are currently made, once a commitment
        # is timestamped by Bitcoin this response will never change.
        self.send_header('Cache-Control', 'public, max-age=3600')

        self.send_header('Content-type', 'application/octet-stream')
        self.end_headers()

        timestamp.serialize(StreamSerializationContext(self.wfile))

    def do_POST(self):
        if self.path == '/digest':
            self.post_digest()

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')

            # a 404 is only going to become not a 404 if the server is upgraded
            self.send_header('Cache-Control', 'public, max-age=3600')

            self.end_headers()
            self.wfile.write(b'not found')

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')

            # Humans are likely to be refreshing this, so keep it up-to-date
            self.send_header('Cache-Control', 'public, max-age=1')

            self.end_headers()

            proxy = bitcoin.rpc.Proxy()

            # FIXME: Unfortunately getbalance() doesn't return the right thing;
            # need to investigate further, but this seems to work.
            str_wallet_balance = str(proxy._call("getbalance"))

            welcome_page = """\
<html>
<head>
    <title>OpenTimestamps Calendar Server</title>
</head>
<body>
<p>This is an <a href="http://www.opentimestamps.org">OpenTimestamps</a> Calendar.</p>

<p>
Pending commitments: %d</br>
Transactions waiting for confirmation: %d</br>
Best-block: %s, height %d</br>
</br>
Wallet balance: %s BTC</br>
</p>

<p>
You can donate to the wallet by sending funds to %s</br>
This address changes after every donation.
</p>

</body>
</html>
""" % (len(self.calendar.stamper.pending_commitments),
       len(self.calendar.stamper.txs_waiting_for_confirmation),
       bitcoin.core.b2lx(proxy.getbestblockhash()), proxy.getblockcount(),
       str_wallet_balance,
       str(proxy.getaccountaddress('')))

            self.wfile.write(welcome_page.encode())

        elif self.path.startswith('/timestamp/'):
            self.get_timestamp()
        elif self.path.startswith('/insight-api/block/'):
            try:
                block = self.get_block_from_hash(self.path[len('/insight-api/block/'):])
                self.write_block_header(block)
            except Exception as err:
                logging.error(err)
                self.send_response(500)
        elif self.path.startswith('/insight-api/block-index/'):
            try:
                block_hash = self.get_block_hash_from_height(self.path[len('/insight-api/block-index/'):])
                self.write_block_hash(block_hash)
            except Exception as err:
                logging.error(err)
                self.send_response(500)
        elif self.path.startswith('/insight-api/block-from-index/'):
            try:
                block_hash = self.get_block_hash_from_height(self.path[len('/insight-api/block-from-index/'):])
                block = self.get_block_from_hash(block_hash['blockHash'])
                self.write_block_header(block)
            except Exception as err:
                logging.error(err)
                self.send_response(500)
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            # a 404 is only going to become not a 404 if the server is upgraded
            self.send_header('Cache-Control', 'public, max-age=3600')
            self.end_headers()
            self.wfile.write(b'Not found')

    def write_block_hash(self, block_hash):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(block_hash).encode('utf-8'))

    def write_block_header(self, block):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Cache-Control', 'public, max-age=3600')
        self.end_headers()
        self.wfile.write(json.dumps(block).encode('utf-8'))

    @staticmethod
    def get_block_from_hash(block_hash):
        proxy = bitcoin.rpc.Proxy()
        getblockheader = proxy.getblockheader(bytes.fromhex(block_hash)[::-1])
        result = {
            'merkleroot': bytes.hex(getblockheader.hashMerkleRoot[::-1]),
            'time':getblockheader.nTime,
            'hashPrevBlock' : bytes.hex(getblockheader.hashPrevBlock[::-1]),
            'nonce':getblockheader.nNonce,
            'version':getblockheader.nVersion
        }

        return result

    @staticmethod
    def get_block_hash_from_height(block_height):
        proxy = bitcoin.rpc.Proxy()
        getblockhash = proxy.getblockhash(int(block_height))
        result = {'blockHash': bytes.hex(getblockhash[::-1])}
        return result


class StampServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    def __init__(self, server_address, aggregator, calendar):
        class rpc_request_handler(RPCRequestHandler):
            pass
        rpc_request_handler.aggregator = aggregator
        rpc_request_handler.calendar = calendar

        super().__init__(server_address, rpc_request_handler)

    def serve_forever(self):
        super().serve_forever()
