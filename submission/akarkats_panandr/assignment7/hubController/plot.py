import matplotlib.pyplot as plt
import sys

ping_id = []
rtt = []

with open('ping_1-2.out', 'r') as f:
    for idx, line in enumerate(f):
        #print idx, line
        ping_id.append(idx)
        rtt.append(float(line.strip('\n')))

plt.title("Simple Hub: PING between H1 and H2")
plt.xlabel("ICMP packet ID")
plt.ylabel("RTT time")

axes = plt.gca()
axes.set_ylim([0, 100])

plt.plot(ping_id, rtt)
plt.savefig("ping-h1-h2.png")

plt.clf()

ping_id = []
rtt = []

with open('ping_1-5.out', 'r') as f:
    for idx, line in enumerate(f):
        #print idx, line
        ping_id.append(idx)
        rtt.append(float(line.strip('\n')))

plt.title("Simple Hub: PING between H1 and H5")
plt.xlabel("ICMP packet ID")
plt.ylabel("RTT time (ms)")

axes = plt.gca()
axes.set_ylim([0, 120])

plt.grid()

plt.plot(ping_id, rtt)

plt.savefig("ping-h1-h5.png")
