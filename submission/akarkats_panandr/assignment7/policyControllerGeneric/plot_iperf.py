import matplotlib.pyplot as plt
import sys

intervals = [i for i in xrange(0,20,2)]
throughputs_h1_h3 = []
throughputs_h1_h4 = []


with open('iperf_gen_h1_h3.out', 'r') as f:
    for line in f:
        throughputs_h1_h3.append(line)

with open('iperf_gen_h1_h4.out', 'r') as f:
    for line in f:
        throughputs_h1_h4.append(line)

plt.title("Policy controller: Throughput")
plt.xlabel("Interval (sec)")
plt.ylabel("Throughput (Gbits/s)")

axes = plt.gca()
axes.set_ylim([0, 50])

line_1 = plt.plot(intervals, throughputs_h1_h3, label = "h1 -> h3")
line_2 = plt.plot(intervals, throughputs_h1_h4, label = "h1 -> h4")

plt.grid()
plt.legend(loc='lower right')
plt.savefig("gen_iperf_policy.png")

plt.show()
