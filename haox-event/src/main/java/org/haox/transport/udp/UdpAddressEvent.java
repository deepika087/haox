package org.haox.transport.udp;

import org.haox.transport.event.AddressEvent;

import java.net.InetSocketAddress;

public class UdpAddressEvent {

    public static AddressEvent createAddressBindEvent(InetSocketAddress address) {
        return new AddressEvent(address, UdpEventType.ADDRESS_BIND);
    }

    public static AddressEvent createAddressConnectEvent(InetSocketAddress address) {
        return new AddressEvent(address, UdpEventType.ADDRESS_CONNECT);
    }

}
