import matplotlib.pyplot as plt

timeouts = []
perf1 = []
perf2 = []

with open('timeouts.txt', 'r') as f:
    for line in f:
        timeouts.append(line.split()[0])
        perf1.append(line.split()[1])
        perf2.append(line.split()[2])

plt.title("Policy Controller: Throughput for different flow paths.")
plt.xlabel("hard_timeout for rules (sec)")
plt.ylabel("Throughput (Gbps)")

#axes = plt.gca()
#axes.set_ylim([0, 140])
#axes.set_xlim([0,100])

# Plot throughput for h1->h4
line_1 = plt.plot(timeouts, perf1, label="h1 -> h4")
# Plot throughput for h1->h3
line_2 = plt.plot(timeouts, perf2, label="h1 -> h3")

plt.legend(loc='lower right')
plt.grid()

plt.savefig("timeouts.png")

