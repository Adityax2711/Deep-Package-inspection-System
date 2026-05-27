import java.util.HashSet;
import java.util.Set;

public class RuleEngine {
    private final Set<String> blockedDomains = new HashSet<>();
    private final Set<String> blockedIps = new HashSet<>();

    public RuleEngine() {
        // Initialize active firewall blocking rules
        blockedDomains.add("badsite.com");
        blockedDomains.add("youtube.com");
        blockedIps.add("192.168.1.50");
    }

    public boolean shouldDrop(Packet pkt) {
        if (blockedDomains.contains(pkt.sni)) {
            return true;
        }
        return blockedIps.contains(pkt.srcIp) || blockedIps.contains(pkt.dstIp);
    }
}