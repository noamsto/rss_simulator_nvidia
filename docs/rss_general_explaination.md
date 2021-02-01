# RSS (Receive Side Scaling)

Receive side scaling (RSS) is a network driver technology that enables the efficient distribution of network receive processing across multiple CPUs in multiprocessor systems.

## Resources

1. [RSS Introduction](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-receive-side-scaling)
2. [Toeplitz Hash Algorithm](https://en.wikipedia.org/wiki/Toeplitz_Hash_Algorithm)
3. ethtool useful commands:
    1. ethtool -x - View the receive flow hash indirection table
    2. ethtool -X equal N - Sets the receive flow hash indirection table to spread flows evenly between the first N receive queues.
    3. ethtool -X weight - Sets the receive flow hash indirection table to spread flows between receive queues according to the given weights. The sum of the weights must be non-zero and must not exceed the size of the indirection table.

## Future - features

* Select what will be the fields used for the RSS function \
  i.e:
    1. RSS only on IPs
    2. Only on UDPs
* Use pcap as input.
