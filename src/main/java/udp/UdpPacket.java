package udp;

import java.nio.ByteBuffer;

/**
 * A data packet consisting of the fixed UDP header, a possibly empty list of
 * contributing sources, and the payload data.
 *
 * @author Tony Lim
 */

public class UdpPacket {

    public static final int RTP_PACKET_MAX_SIZE = 8192;

    /**
     *
     */
    private static final long serialVersionUID = -1590053946635208723L;

    /**
     * The size of the fixed part of the RTP header as defined by RFC 3550.
     */
    public static final int PORT_SIZE = 2;

    public static final int FIXED_HEADER_SIZE = 6;

    /**
     * The size of the extension header as defined by RFC 3550.
     */
    public static final int LENGTH_SIZE = 2;

    private ByteBuffer buffer;

    public UdpPacket(int capacity, boolean allocateDirect) {
        this.buffer = allocateDirect ? ByteBuffer.allocateDirect(capacity) : ByteBuffer.allocate(capacity);
    }

    public ByteBuffer getBuffer() {
        return buffer;
    }

    public long getSrcPort() {
        return (((long)(buffer.get(0) & 0xff) << 8)  |
                (long)(buffer.get(1) & 0xff));
    }

    public long getDstPort() {
        return (((long)(buffer.get(2) & 0xff) << 8)  |
                (long)(buffer.get(3) & 0xff));
    }

    public long getUDPLength() {
        return (((long)(buffer.get(4) & 0xff) << 8)  |
                (long)(buffer.get(5) & 0xff));
    }

    @Override
    public String toString() {
        return "UDP Packet[SrcPort=" + getSrcPort() + ", DstPort=" + getDstPort() +
                ", UDPLength=" + getUDPLength() + "]";
    }

}
