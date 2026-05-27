import java.util.Objects;

public class Packet {
    public final String srcIp;
    public final String dstIp;
    public final int srcPort;
    public final int dstPort;
    public final String protocol;
    public final String sni; // Server Name Indication
    public final long payloadBytes;

    public Packet(String srcIp, String dstIp, int srcPort, int dstPort, String protocol, String sni,
            long payloadBytes) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
        this.sni = sni;
        this.payloadBytes = payloadBytes;
    }

    // Generate a deterministic hash based on the network 5-tuple to identify
    // connection flows
    public int compute5TupleHash() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}