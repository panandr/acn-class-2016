import matplotlib.pyplot as plt

"""
Plot ping trace for microflow controller.
"""

ping_id = []
rtt = []

with open('mls_ping12', 'r') as f:
    for idx, line in enumerate(f):
        #print idx, line
        ping_id.append(idx)
        rtt.append(float(line.strip('\n')))

plt.title("Microflow controller: PING between H1 and H2")
plt.xlabel("ICMP packet ID")
plt.ylabel("RTT time (ms)")

axes = plt.gca()
axes.set_ylim([0, 70])
axes.set_xlim([-2,100])

plt.plot(ping_id, rtt)
plt.savefig("mls_12_ping.png")

"""
Plot throughput for different hard timeout values.
iperf is used to measure the througput.
"""

plt.clf()

timeouts = []
perf = []

with open('timeouts.txt', 'r') as f:
    for line in f:
        timeouts.append(line.split()[0])
        perf.append(line.split()[1])

plt.title("Microflow controller: Throughput vs hard_timeout values for the rules")
plt.xlabel("hard_timeout for rules (sec)")
plt.ylabel("Throughput (Gbps)")

plt.grid()

axes = plt.gca()
#axes.set_ylim([0, 140])
#axes.set_xlim([0,100])

plt.plot(timeouts, perf)
plt.savefig("timeouts.png")

