# Command Lines
This text file shows the command lines used in the development process. 

### Start PCAP capture
In order to start the pcap capture, you need to use this command line:

```
tshark -i en0 -a duration:3600 -w baseline_day1.pcap
```

This command uses wireshark's command line interface (CLI) and is in inspect mode to inspect en0 (wifi in macs). It analyses all packages with the -a (autostop for 1 hour) settings. It listens the network traffic for an hour and then logs it in the baseline_day1.pcap file.

It is important to run this script for 3-5 days to get useful and enough data for our ml model and inspection. 

### Install Python Dependencies
You need to install the python 3.13 to be able to use this project.
 python_reqs.txt file contains all dependencies for this project.

 This code gets all the dependencies in the active environment. (My environment is a conda env named PackageTracer.)
 ```
pip list --format==freeze > python_reqs.txt

 ```

## !! I need to delete the pcap files before uploding this repository to the github because pcap file is too big for github(approximately = 700mb of data).