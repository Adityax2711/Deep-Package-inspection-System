import java.util.*;
import java.util.concurrent.*;

public class DPIEngine {
    private final int numLoadBalancers = 2;
    private final int numFastPaths = 4; // 2 fast paths allocated per load balancer

    private final List<LinkedBlockingQueue<Packet>> lbQueues = new ArrayList<>();
    private final List<LinkedBlockingQueue<Packet>> fpQueues = new ArrayList<>();

    private final List<WorkerMetrics> fpMetrics = new ArrayList<>();
    private final RuleEngine ruleEngine = new RuleEngine();
    private final ExecutorService threadPool = Executors.newFixedThreadPool(numLoadBalancers + numFastPaths);

    // Poison Pill object pattern used to gracefully signal threads to shut down
    public static final Packet POISON_PILL = new Packet("", "", 0, 0, "", "", 0);

    public DPIEngine() {
        for (int i = 0; i < numLoadBalancers; i++) {
            lbQueues.add(new LinkedBlockingQueue<>());
        }
        for (int i = 0; i < numFastPaths; i++) {
            fpQueues.add(new LinkedBlockingQueue<>());
            fpMetrics.add(new WorkerMetrics());
        }
    }

    public void start() {
        for (int i = 0; i < numLoadBalancers; i++) {
            final int lbIndex = i;
            threadPool.submit(() -> runLoadBalancer(lbIndex));
        }
        for (int i = 0; i < numFastPaths; i++) {
            final int fpIndex = i;
            threadPool.submit(() -> runFastPath(fpIndex));
        }
    }

    private void runLoadBalancer(int lbIndex) {
        try {
            while (true) {
                Packet pkt = lbQueues.get(lbIndex).take();
                if (pkt == POISON_PILL) {
                    fpQueues.get(lbIndex * 2).put(POISON_PILL);
                    fpQueues.get(lbIndex * 2 + 1).put(POISON_PILL);
                    break;
                }

                int hashVal = Math.abs(pkt.compute5TupleHash());
                int localFpIndex = hashVal % (numFastPaths / numLoadBalancers);
                int globalFpIndex = (lbIndex * 2) + localFpIndex;

                fpQueues.get(globalFpIndex).put(pkt);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void runFastPath(int fpIndex) {
        try {
            WorkerMetrics metrics = fpMetrics.get(fpIndex);
            while (true) {
                Packet pkt = fpQueues.get(fpIndex).take();
                if (pkt == POISON_PILL) {
                    break;
                }

                // Core Inspection Logic
                if (ruleEngine.shouldDrop(pkt)) {
                    metrics.recordDroppedPacket(pkt.payloadBytes);
                } else {
                    metrics.recordForwardedPacket(pkt.sni, pkt.payloadBytes);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void injectPacket(Packet pkt) {
        int hashVal = Math.abs(pkt.compute5TupleHash());
        int lbIndex = hashVal % numLoadBalancers;
        try {
            lbQueues.get(lbIndex).put(pkt);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void shutdown() {
        try {
            for (int i = 0; i < numLoadBalancers; i++) {
                lbQueues.get(i).put(POISON_PILL);
            }
            threadPool.shutdown();
            threadPool.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            threadPool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public void printStatisticsReport() {
        long totalPkts = 0;
        long totalBytes = 0;
        long totalForwarded = 0;
        long totalDropped = 0;
        Map<String, Long> globalApps = new HashMap<>();

        System.out.println("\n========================================");
        System.out.println("     DEEP PACKET INSPECTION REPORT (JAVA)  ");
        System.out.println("========================================");

        for (int i = 0; i < numFastPaths; i++) {
            WorkerMetrics m = fpMetrics.get(i);
            System.out.printf("FastPath Worker Thread [%d] -> Processed: %d packets | Drops: %d%n",
                    i, m.packetsProcessed.get(), m.packetsDropped.get());

            totalPkts += m.packetsProcessed.get();
            totalBytes += m.bytesProcessed.get();
            totalForwarded += m.packetsForwarded.get();
            totalDropped += m.packetsDropped.get();

            m.appBreakdown.forEach((app, count) -> globalApps.merge(app, count, Long::sum));
        }

        System.out.println("\n--- Engine Traffic Aggregations ---");
        System.out.println("Total Network Packets Audited : " + totalPkts);
        System.out.println("Total Data Volume Inspected   : " + totalBytes + " Bytes");
        System.out.println("Packets Successfully Forwarded: " + totalForwarded);
        System.out.println("Packets Intercepted & Dropped : " + totalDropped);

        System.out.println("\n--- Application Classification (Forwarded) ---");
        globalApps
                .forEach((app, count) -> System.out.println(" * " + app + " : " + count + " valid packets verified."));
        System.out.println("========================================\n");
    }
}