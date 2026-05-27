import java.util.Arrays;
import java.util.List;

public class DPIEngineApp {
    public static void main(String[] args) throws InterruptedException {
        DPIEngine engine = new DPIEngine();
        engine.start();

        System.out.println("[System Initialization] Java DPI Engine actively monitoring pipelines...");

        // Stream of incoming packets to feed into the pipeline
        List<Packet> packetStream = Arrays.asList(
                new Packet("10.0.0.1", "142.250.190.46", 49152, 443, "TCP", "google.com", 1200),
                new Packet("10.0.0.2", "192.168.1.50", 51234, 80, "TCP", "local-nas.internal", 500), // Dropped (Blocked
                                                                                                     // IP)
                new Packet("10.0.0.3", "172.217.16.14", 49800, 443, "TCP", "youtube.com", 1500), // Dropped (Blocked
                                                                                                 // Domain)
                new Packet("10.0.0.4", "31.13.71.36", 52100, 443, "TCP", "instagram.com", 900),
                new Packet("10.0.0.1", "142.250.190.46", 49152, 443, "TCP", "google.com", 1100), // Shares same
                                                                                                 // connection map
                                                                                                 // stream
                new Packet("10.0.0.5", "104.16.248.249", 55432, 443, "UDP", "badsite.com", 350) // Dropped (Blocked
                                                                                                // Domain)
        );

        // Dynamically inject stream packets into pipelines
        for (Packet pkt : packetStream) {
            engine.injectPacket(pkt);
            Thread.sleep(50); // Simulates interval timing gaps between arrivals
        }

        // Give worker threads time to finish handling internal structures
        Thread.sleep(500);

        engine.shutdown();
        engine.printStatisticsReport();
    }
}