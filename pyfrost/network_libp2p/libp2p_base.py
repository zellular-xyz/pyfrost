# Importing necessary libp2p components
import timeit
from libp2p.typing import TProtocol
import libp2p.crypto.ed25519 as ed25519
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.crypto.secp256k1 import create_new_key_pair
from libp2p.host.basic_host import BasicHost
from libp2p.network.swarm import Swarm
from libp2p.peer.id import ID as PeerID
from libp2p.peer.peerstore import PeerStore
import libp2p.security.secio.transport as secio
import libp2p.security.noise.transport as noise
from libp2p.stream_muxer.mplex.mplex import MPLEX_PROTOCOL_ID, Mplex
from libp2p.transport.tcp.tcp import TCP
from libp2p.transport.upgrader import TransportUpgrader
from libp2p.host.host_interface import IHost

from typing import Dict
import types
import logging
import trio
import multiaddr
import json

PROTOCOLS_ID = {
    'round1': TProtocol('/muon/1.0.0/round1'),
    'round2': TProtocol('/muon/1.0.0/round2'),
    'round3': TProtocol('/muon/1.0.0/round3'),
    'generate_nonces': TProtocol('/muon/1.0.0/generate-nonces'),
    'sign': TProtocol('/muon/1.0.0/sign'),
}


class RequestObject:
    def __init__(self, request_id: str, call_method: str, parameters: Dict,
                 data: Dict = None) -> None:
        self.request_id: str = request_id
        self.call_method: str = call_method
        self.parameters: Dict = parameters
        self.data = data

    def get(self):
        result = {
            'request_id': f'{self.request_id}_{self.call_method}',
            'method': self.call_method,
            'parameters': self.parameters
        }
        if self.data:
            result['data'] = self.data
        return result


class Libp2pBase:

    def __init__(self, address: Dict[str, str], secret: str, host: IHost = None) -> None:

        # TODO: check this procedure to create host
        self._key_pair = create_new_key_pair(bytes.fromhex(secret))
        self.peer_id: PeerID = PeerID.from_pubkey(self._key_pair.public_key)
        if host is not None:
            self.host = host
        else:
            peer_store = PeerStore()
            peer_store.add_key_pair(self.peer_id, self._key_pair)

            muxer_transports_by_protocol = {MPLEX_PROTOCOL_ID: Mplex}
            noise_key = ed25519.create_new_key_pair()
            security_transports_by_protocol = {
                TProtocol(secio.ID): secio.Transport(self._key_pair),
                TProtocol(noise.PROTOCOL_ID): noise.Transport(self._key_pair, noise_key.private_key)
            }
            upgrader = TransportUpgrader(
                security_transports_by_protocol, muxer_transports_by_protocol)
            transport = TCP()
            swarm = Swarm(self.peer_id, peer_store, upgrader, transport)

            self.host: IHost = BasicHost(swarm)

        self.ip: str = address['host']
        self.port: str = address['port']

        self.protocol_list: Dict[str, TProtocol] = {}
        self.protocol_handler: Dict[str, types.FunctionType] = {}
        self.__is_running = False

    def set_protocol_and_handler(self, protocol_list: Dict[str, TProtocol], protocol_handler: Dict[str, types.FunctionType]) -> None:

        self.protocol_list = protocol_list
        self.protocol_handler = protocol_handler

    async def run(self) -> None:

        self.__is_running = True
        listen_addr = multiaddr.Multiaddr(f'/ip4/{self.ip}/tcp/{self.port}')
        async with self.host.run(listen_addrs=[listen_addr]):
            for protocol_name, handler in self.protocol_handler.items():
                self.host.set_stream_handler(
                    self.protocol_list[protocol_name], handler)
            logging.info(
                f'API: /ip4/{self.ip}/tcp/{self.port}/p2p/{self.host.get_id().pretty()}')
            logging.info('Waiting for incoming connections...')
            while self.__is_running:
                await trio.sleep(1)

    def stop(self) -> None:

        self.__is_running = False

    async def send(self, destination_address: Dict[str, str], destination_peer_id: PeerID, protocol_id: TProtocol,
                   message: Dict, result: Dict = None, timeout: float = 5.0, semaphore: trio.Semaphore = None) -> None:
        if semaphore is not None:
            async with semaphore:
                await self.__send(destination_address, destination_peer_id, protocol_id,
                                  message, result, timeout)
        else:
            await self.__send(destination_address, destination_peer_id, protocol_id,
                              message, result, timeout)

    async def __send(self, destination_address: Dict[str, str], destination_peer_id: PeerID, protocol_id: TProtocol,
                     message: Dict, result: Dict = None, timeout: float = 5.0) -> None:

        now = timeit.default_timer()
        destination = f'/ip4/{destination_address["host"]}/tcp/{destination_address["port"]}/p2p/{destination_peer_id}'
        logging.info(
            f'{destination_peer_id}{protocol_id} destination: {destination}')
        maddr = multiaddr.Multiaddr(destination)
        info = info_from_p2p_addr(maddr)
        with trio.move_on_after(timeout) as cancel_scope:
            try:
                await self.host.connect(info)
                logging.debug(
                    f'{destination_peer_id}{protocol_id} Connected to peer.')

                stream = await self.host.new_stream(info.peer_id, [protocol_id])

                logging.debug(
                    f'{destination_peer_id}{protocol_id} Opened a new stream to peer')

                encoded_message = json.dumps(message).encode('utf-8')
                await stream.write(encoded_message)
                logging.debug(
                    f'{destination_peer_id}{protocol_id} Sent message: {json.dumps(message, indent=4)}')

                await stream.close()
                logging.debug(
                    f'{destination_peer_id}{protocol_id} Closed the stream')

                if result is not None:
                    response = await stream.read()
                    result[destination_peer_id] = json.loads(
                        response.decode('utf-8'))
                    logging.debug(
                        f'{destination_peer_id}{protocol_id} Received response: {json.dumps(result[destination_peer_id], indent=4)}')
                    then = timeit.default_timer()
                    logging.debug(
                        f'{destination_peer_id}{protocol_id} takes: {then - now} seconds.')

            except Exception as e:
                logging.error(
                    f'{destination_peer_id}{protocol_id} libp2p_base => Exception occurred: {type(e).__name__}: {e}')
                response = {
                    'status': 'ERROR',
                    'error': f'An exception occurred: {type(e).__name__}: {e}',
                }
                if result is not None:
                    result[destination_peer_id] = response

        if cancel_scope.cancelled_caught:
            logging.error(
                f'{destination_peer_id}{protocol_id} libp2p_base => Timeout error occurred')
            timeout_response = {
                'status': 'TIMEOUT',
                'error': 'Communication timed out',
            }
            if result is not None:
                result[destination_peer_id] = timeout_response
