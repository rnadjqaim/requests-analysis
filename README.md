# log analyzer with tkinter

this repository contains a python application built with tkinter for analyzing access logs. the application supports features like:

- local log file analysis
- ssh integration to fetch logs from remote servers
- detection of bots, 4xx and 5xx requests, static content requests
- option to save analysis as a csv report

## features

1. log file analysis:
   - analyze local log files for bot detection, http status codes, and request patterns.

2. ssh integration:
   - connect to remote servers using ssh to fetch logs.

3. save reports:
   - export analysis results to csv.

4. intuitive gui:
   - user-friendly interface with buttons for file selection, ssh connection, analysis, and report saving.

## prerequisites

- python 3.x
- `paramiko` library for ssh functionality.

install `paramiko` using pip:
```bash
pip install paramiko
```

## usage

1. clone the repository:
   ```bash
   git clone https://github.com/yourusername/log-analyzer-tkinter.git
   cd log-analyzer-tkinter
   ```

2. run the application:
   ```bash
   python log_analyzer.py
   ```

3. use the gui to:
   - select a local log file or specify ssh details to fetch logs from a remote server.
   - analyze logs for bots, 4xx/5xx requests, and static content.
   - save results as a csv file.

## file structure

```
log-analyzer-tkinter/
|-- log_analyzer.py  # main application file
|-- readme.md        # documentation
```

## example access log

you can test the application using a sample access log file included in the `examples/` directory.

## license

this project is licensed under the mit license. see the license file for details.
