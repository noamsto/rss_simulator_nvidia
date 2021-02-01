# Nvidia Toeplitz RSS Simulator

## Introduction

This tool aims to simulate Nvidia's NIC RSS simulation using the Toeplitz hash function.
Histogram and queues distribution is generated for a given 40 bytes hash-key and a data-set of 4 tuples IPv4 addresses.

Installation:

1. Extract rss_simulator.tar:
`tar -xvf rss_simulator.tar -C /tmp/`
2. Run installation script (requires internet):
`cd /tmp/rss_simulator`
`./install_rss_simulator.sh`
To install with custom python version run:
`pip# install dist/rss_simulator_nvidia-0.0.1-py2.py3-none-any.whl`

## Usage

The input required for this tool to work properly is as follows:

1. Hash-table size. i.e.: 128
2. A number of configured queues. i.e. 24.
3. Hash-key 40 bytes length. i.e.:
23:0d:44:3d:8c:2c:6e:64:d4:1a:f3:44:49:9b:21:74:fd:1a:9d:c1:dd:76:77:37:38:51:66:85:7b:dc:48:a8:3e:55:08:c1:63:af:01:9d
4. A CSV containing 4 tuples of IPv4 addresses. i.e.:

| src_ip  | dst_ip | src_port | dst_port|
|---------|--------|---------|---------|
| 3.3.3.1 | 3.3.3.2 | 5201 | 5001|
| 3.3.3.1 | 3.3.3.2 | 5202 | 5001|
| 3.3.3.1 | 3.3.3.2 | 5203 | 5001|
| 3.3.3.1 | 3.3.3.2 | 5204 | 5001|

There are 2 possible outputs, Histogram or CSV file containing statistics.

### Histogram

To generate flows (4 tuples) count per queue histogram run:

```bash
rss-simulator --key-file <KEY_FILE> --ips-file <IPS_CSV> --htable-size <NUM> --num-queues <NUM>
```

### CSV output

To generate a CSV file containing the number of flows per queue as well as the hash result and queue number per flow, run:

```bash
rss-simulator --key-file <KEY_FILE> --ips-file <IPS_CSV> --htable-size <NUM> --num-queues <NUM> --csv <CSV_PATH>
```

## Example

Accompanied with this tool there is an "example_input" directory containing an example hash-key and IPs data-set.
Here is the execution output for the histogram and CSV output for the mentioned input files.

### Histogram Output

```bash
rss-simulator --key-file example_input/hash_key.txt --ips-file example_input/ips.csv  --htable-size 128 --num-queues 24
```

<img src="https://raw.githubusercontent.com/noamsto/rss_simulator_nvidia/master/res/histogram_output.png"
width="" height="">

### CSV Output

```bash
rss-simulator --key-file example_input/hash_key.txt --ips-file example_input/ips.csv  --htable-size 128 --num-queues 24 --csv out.csv
```

The trimmed output of "out.csv" content:

| queue_number | counts |
|---|---|
| 0  | 4 |
| 1  | 3 |
| 2  | 3 |
| 3  | 4 |
| 4  | 3 |
| 5  | 4 |
| 6  | 3 |
| 7  | 2 |
| 8  | 8 |
| 9  | 7 |
| 10 | 7 |
| 11 | 7 |
| 12 | 2 |
| 13 | 2 |
| 14 | 2 |
| 15 | 2 |
| 16 | 2 |
| 17 | 2 |
| 18 | 2 |
| 19 | 2 |
| 20 | 7 |
| 21 | 7 |
| 22 | 8 |
| 23 | 7 |

|src_ip|dst_ip|src_port|dst_port|hash_result|queue_number|
|---|---|---|---|---|---|
|3.3.3.1|3.3.3.2|5201|5001|3151101778|10|
|3.3.3.1|3.3.3.2|5202|5001|2124597753|1|
|3.3.3.1|3.3.3.2|5203|5001|117501236|4|
|3.3.3.1|3.3.3.2|5204|5001|2619036332|20|
|3.3.3.1|3.3.3.2|5205|5001|3854136929|1|
|3.3.3.1|3.3.3.2|5206|5001|550125770|2|
|3.3.3.1|3.3.3.2|5207|5001|1500013575|7|
|3.3.3.1|3.3.3.2|5208|5001|1833410310|6|
|3.3.3.1|3.3.3.2|5209|5001|350600139|3|
|3.3.3.1|3.3.3.2|5210|5001|3516304736|0|
|3.3.3.1|3.3.3.2|5211|5001|2822023597|21|
|3.3.3.1|3.3.3.2|5212|5001|858723893|5|
|3.3.3.1|3.3.3.2|5213|5001|1250767608|0|
|3.3.3.1|3.3.3.2|5214|5001|2415789139|11|
|3.3.3.1|3.3.3.2|5215|5001|4133232798|6|
|3.3.3.1|3.3.3.2|5216|5001|2116348149|21|
|3.3.3.1|3.3.3.2|5217|5001|126274616|8|
|3.3.3.1|3.3.3.2|5218|5001|3270900371|19|
|3.3.3.1|3.3.3.2|5219|5001|3143097950|22|
|3.3.3.1|3.3.3.2|5220|5001|541876678|22|
| ...|  | | | | |
