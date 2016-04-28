import matplotlib.pyplot as plt
import sys

"""
Plot ping trace for microflow controller.
"""

ping_id = []
rtt = []

with open('mls_12_ping.out', 'r') as f:
    for idx, line in enumerate(f):
        #print idx, line
        ping_id.append(idx)
        rtt.append(float(line.strip('\n')))

plt.title("Microflow controller: PING between H1 and H2")
plt.xlabel("ICMP packet ID")
plt.ylabel("RTT time")

axes = plt.gca()
axes.set_ylim([0, 140])
axes.set_xlim([0,100])

plt.plot(ping_id, rtt)
plt.savefig("mls_12_ping.png")

"""
Plot throughput for different hard timeout values.
iperf is used to measure the througput.
"""

plt.clf()

timeouts = []
perf = []

with open('throughput_vs_timeout.txt', 'r') as f:
    for line in f:
        timeouts.append(line.split()[0])
        perf.append(line.split()[1])

plt.title("Microflow controller: Througput vs hard_timeout values for the flows")
plt.xlabel("hard_timeout for flows (sec)")
plt.ylabel("Throughput (Gbps)")

axes = plt.gca()
#axes.set_ylim([0, 140])
#axes.set_xlim([0,100])

plt.plot(timeouts, perf)
plt.savefig("timeout.png")