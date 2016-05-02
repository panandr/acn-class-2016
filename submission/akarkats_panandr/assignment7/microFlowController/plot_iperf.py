import matplotlib.pyplot as plt
import sys

intervals = [i for i in xrange(0,20,2)]
throughputs = []

with open('iperf_mls_h1_h5.out', 'r') as f:
    for line in f:
        throughputs.append(line)

plt.title("Microflow controller: Throughput")
plt.xlabel("Interval (sec)")
plt.ylabel("Throughput (Gbits/s)")

axes = plt.gca()
axes.set_ylim([0, 30])

plt.plot(intervals, throughputs)
plt.grid()
plt.savefig("iperf_mls_h1_h5.png")

plt.show()
