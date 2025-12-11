#!/usr/bin/env python

import argparse

from scapy.all import load_layer
from scapy.sendrecv import AsyncSniffer

from meter.flow_session import generate_session_class


def create_sniffer(input_file, input_interface, output_mode, output_file, port, duration, max_packets):
    assert (input_file is None) ^ (input_interface is None)

    NewFlowSession = generate_session_class(output_mode, output_file, duration, max_packets)

    if input_file is not None:
        return AsyncSniffer(offline=input_file, filter=f'udp port {port}', prn=None, session=NewFlowSession, store=False)
    else:
        return AsyncSniffer(iface=input_interface, filter=f'udp port {port}', prn=None,
                            session=NewFlowSession, store=False)


def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-n', '--online', '--interface', action='store', dest='input_interface',
                             help='capture online data from INPUT_INTERFACE')
    input_group.add_argument('-f', '--offline', '--file', action='store', dest='input_file',
                             help='capture offline data from INPUT_FILE')

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument('-c', '--csv', '--flow', action='store_const', const='flow', dest='output_mode',
                              help='output flows as csv')
    output_group.add_argument('-s', '--json', '--sequence', action='store_const', const='sequence', dest='output_mode',
                              help='output flow segments as json')

    parser.add_argument('output', help='output file name (in flow mode) or directory (in sequence mode)')
    parser.add_argument('--port', type=int, default=853, help='UDP port to filter (default: 853)')
    parser.add_argument('--duration', type=float, default=120.0, help='Max flow duration in seconds (default: 120.0)')
    parser.add_argument('--max-packets', type=int, default=0, help='Max packets per flow (default: 0 = unlimited)')
    args = parser.parse_args()

    load_layer('tls')

    sniffer = create_sniffer(args.input_file, args.input_interface, args.output_mode, args.output, args.port, args.duration, args.max_packets)
    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()
        if hasattr(sniffer, '_sniffer') and hasattr(sniffer._sniffer, 'session'):
            if hasattr(sniffer._sniffer.session, 'garbage_collect'):
                sniffer._sniffer.session.garbage_collect(None)


if __name__ == '__main__':
    main()
