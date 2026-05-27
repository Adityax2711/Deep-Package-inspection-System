# Deep-Package-inspection-System
A modern, concurrent Deep Packet Inspection (DPI) system leveraging Java Virtual Threads for scalable, high-throughput packet processing. Implements stateful stream assembly, application-layer protocol identification, and real-time network traffic signature analysis.
#  High-Performance Deep Packet Inspection (DPI) Engine

A modern, concurrent Deep Packet Inspection (DPI) system engineered in **Java 21+**. This system harnesses **Java Virtual Threads (Project Loom)** to achieve massive throughput and low-latency packet analysis across Application Layer (Layer 7) protocols without the traditional overhead of OS-level thread blocking.

##  System Architecture & Data Flow
The engine is built on a decoupled, non-blocking pipeline where packet data ingestion is entirely separated from payload inspection and metrics logging. 

### Visual Pipeline Architecture
*GitHub automatically renders the flowchart below:*

mermaid
graph TD
    A[ Network Traffic Stream] -->|1. Ingests Raw Frames| B( DPIEngineApp)
    B -->|2. Instantiates Objects| C[ Packet.java Data Model]
    C -->|3. Dispatches Task| D[⚙️ DPIEngine Concurrency Pool]
    D -->|4. Spawns M:N Carrier Thread| E[ Java Virtual Threads]
    E -->|5. Deep Payload Scan| F[ RuleEngine.java]
    F -->|6. Classify / Match Signatures| G{Threat / Protocol Match?}
    G -->|7. Non-blocking Atomic Updates| H[ WorkerMetrics Telemetry]
Architectural Deep-Dive
The Ingestion Layer (DPIEngineApp): Acts as the network interface simulator, generating or streaming high-velocity traffic into the system pipeline.

The Data Layer (Packet.java): An immutable data structure holding parsed header info (IPs, Ports, Protocol) and the target raw byte/string payload. Because it is immutable, it can be safely read across multiple concurrent threads without synchronization locks.

The Concurrency Layer (DPIEngine): Instead of assigning one heavy OS thread per packet or stream, the engine uses a Virtual Thread executor (Executors.newVirtualThreadPerTaskExecutor()).

How it works: Millions of virtual threads are multiplexed onto a tiny pool of physical OS "carrier" threads. If a virtual thread encounters heavy computational matching or parsing delay, the carrier thread automatically detaches and picks up the next incoming packet.

The Analysis Layer (RuleEngine): The deterministic brain of the system. It processes incoming payloads against a compilation of application signatures (HTTP, SSH, FTP) and malicious pattern regexes.

The Telemetry Layer (WorkerMetrics): A centralized, thread-safe dashboard. Since thousands of virtual threads report inspection results simultaneously, it uses non-blocking atomic variables (AtomicLong, LongAdder) to ensure perfect data accuracy with zero performance degradation.

 Component Breakdown
Packet.java – The fundamental structural unit representing a layer 3/4 wrapper enclosing layer 7 payload metadata.

RuleEngine.java – Contains pattern-matching logic to parse payload details and flag architectural or behavioral anomalies.

WorkerMetrics.java – Safely monitors throughput rates, identified protocol states, and active threat vectors across all active threads.

DPIEngine.java – Orchestrates scheduling, handles thread allocation, and routes tasks efficiently to scale horizontally.

DPIEngineApp.java – The central bootstrapper that configures the environment and drives the lifecycle of the engine.

 Getting Started
Prerequisites
JDK 21 or Higher (Mandatory for virtual thread features).

A standard terminal or Java IDE.

Build & Run via Command Line
1. Clone the repository:

Bash
git clone [https://github.com/Adityax2711/Deep-Package-inspection-System.git](https://github.com/Adityax2711/Deep-Package-inspection-System.git)
cd Deep-Package-inspection-System
2. Compile all source files:

Bash
javac *.java
3. Run the engine:

Bash
java DPIEngineApp
Author
Aditya Raj
