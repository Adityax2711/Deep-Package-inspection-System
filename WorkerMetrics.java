import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class WorkerMetrics {
    public final AtomicLong packetsProcessed = new AtomicLong(0);
    public final AtomicLong bytesProcessed = new AtomicLong(0);
    public final AtomicLong packetsForwarded = new AtomicLong(0);
    public final AtomicLong packetsDropped = new AtomicLong(0);

    // ConcurrentHashMap provides thread-safe access for reporting
    public final ConcurrentHashMap<String, Long> appBreakdown = new ConcurrentHashMap<>();

    public void recordForwardedPacket(String sni, long bytes) {
        packetsProcessed.incrementAndGet();
        bytesProcessed.addAndGet(bytes);
        packetsForwarded.incrementAndGet();
        appBreakdown.merge(sni, 1L, Long::sum);
    }

    public void recordDroppedPacket(long bytes) {
        packetsProcessed.incrementAndGet();
        bytesProcessed.addAndGet(bytes);
        packetsDropped.incrementAndGet();
    }
}