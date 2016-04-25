import matplotlib as plt

with open('ping1-2.out', 'r') as f:
    for idx, line in enumerate(f):
        print idx, line
