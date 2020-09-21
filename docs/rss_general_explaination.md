# RSS (Receive Side Scaling)

Receive side scaling (RSS) is a network driver technology that enables the efficient distribution of network receive processing across multiple CPUs in multiprocessor systems.

## Agenda

1. [RSS Introduction](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-receive-side-scaling)
2. [Toeplitz Hash Algorithm](https://en.wikipedia.org/wiki/Toeplitz_Hash_Algorithm)
3. ethtool example
    1. ethtool -x
    2. ethtool -X equal #
    3. ethtool -X weight
4. RSS Simulator example

## Suggestions

* Select what will be the fields used for the RSS function \
  i.e:
    1. RSS only on IPs
    2. Only on UDPs
* Use pcap as input.
