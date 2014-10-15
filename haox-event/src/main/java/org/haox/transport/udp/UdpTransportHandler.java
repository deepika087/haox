package org.haox.transport.udp;

import org.haox.event.Event;
import org.haox.event.EventType;
import org.haox.transport.Transport;
import org.haox.transport.TransportHandler;
import org.haox.transport.event.TransportEvent;
import org.haox.transport.event.TransportEventType;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Map;

public class UdpTransportHandler extends TransportHandler {

    protected Map<InetSocketAddress, UdpTransport> transports =
            new HashMap<InetSocketAddress, UdpTransport>();

    @Override
    public EventType[] getInterestedEvents() {
        return new EventType[] {
                UdpEventType.CHANNEL_READABLE,
                TransportEventType.TRANSPORT_WRITABLE,
                TransportEventType.TRANSPORT_READABLE,
                TransportEventType.NEW_TRANSPORT
        };
    }

    @Override
    protected void doHandle(Event event) throws Exception {
        EventType eventType = event.getEventType();
        if (eventType == UdpEventType.CHANNEL_READABLE) {
            UdpChannelEvent ce = (UdpChannelEvent) event;
            DatagramChannel channel = ce.getChannel();
            doRead(channel);
        } else if (eventType == TransportEventType.TRANSPORT_READABLE) {
            TransportEvent te = (TransportEvent) event;
            Transport transport = te.getTransport();
            transport.onReadable();
        } else if (eventType == TransportEventType.TRANSPORT_WRITABLE) {
            TransportEvent te = (TransportEvent) event;
            Transport transport = te.getTransport();
            transport.onWriteable();
        }  else if (eventType == TransportEventType.NEW_TRANSPORT) {
            TransportEvent te = (TransportEvent) event;
            Transport transport = te.getTransport();
            if (transport instanceof UdpTransport) {
                InetSocketAddress remoteAddress = transport.getRemoteAddress();
                if (! transports.containsKey(remoteAddress)) {
                    transports.put(remoteAddress, (UdpTransport) transport);
                }
            }
        }
    }

    private void doRead(DatagramChannel channel) throws IOException {
        ByteBuffer recvBuffer = ByteBuffer.allocate(65536); // to optimize
        InetSocketAddress fromAddress = (InetSocketAddress) channel.receive(recvBuffer);
        if (fromAddress != null) {
            recvBuffer.flip();
            UdpTransport transport = transports.get(fromAddress);
            if (transport == null) {
                // should be from acceptor
                transport = new UdpTransport(channel, fromAddress);
                transport.setDispatcher(getDispatcher());
                dispatch(TransportEvent.createNewTransportEvent(transport));
            }
            transport.onRecvData(recvBuffer);
        }
    }

    @Override
    public void helpHandleSelectionKey(SelectionKey selectionKey) throws IOException {
        DatagramChannel channel =
                (DatagramChannel) selectionKey.channel();

        if (selectionKey.isReadable()) {
            dispatch(UdpChannelEvent.makeReadableChannelEvent(channel));
        } else if (selectionKey.isWritable()) {
            dispatch(UdpChannelEvent.makeWritableChannelEvent(channel));
        }
        // Udp channel is always writable, so not usable
        selectionKey.interestOps(SelectionKey.OP_READ);
    }
}
