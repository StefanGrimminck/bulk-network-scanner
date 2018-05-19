import argparse
import sys
import os
import csv
import random


def check_ext(choices):
    """
             choises:    input type: [.IPv4 or .IPv6]

             Function:
             Checks if the file extension is ipv4 or ipv6

             Return value:
             Instance of Act Class
    """

    class Act(argparse.Action):
        def __call__(self, parser, namespace, fname, option_string=None):
            ext = os.path.splitext(fname)[1][1:]
            if ext not in choices:
                option_string = '({})'.format(option_string) if option_string else ''
                parser.error("inputfile doesn't end with one of {}{}".format(choices, option_string))
            else:
                setattr(namespace, self.dest, fname)

    return Act


def split_data(inputfile_shuf, ip_type):
    """
             ipfile_shuf:     Lists with ip's to split
             ip_type:    Type of IP address used.

             Function:
             Removes the port from the records provided by the inputfile

             Return value:
             List with ip addresses
    """

    datafile = "inputlist.txt"

    with open(inputfile_shuf, 'r') as csvfile:
        if ip_type == 'ipv4':
            fp = csv.reader(csvfile, delimiter=':')
        else:
            fp = csv.reader(csvfile, delimiter='.')

        for row in fp:
            with open(datafile, "a") as f:
                f.write(row[0] + '\n')

    os.remove(inputfile_shuf)

    return datafile


def live_host_check(ipfile, ip_type):
    """
          ipfile:     Lists with ip's to scan
          ip_type:    Type of IP address used.

          Function:
          Attempts to find online hosts behind the IP addresses provided as a csv file given as a parameter
          when starting the script.

          Return value:
          List with online hosts
    """
    print('Starting Nmap process ...')

    if ip_type == 'ipv4':
        os.system("nmap -iL inputlist.txt -T5 -n -sn --min-parallelism=100 --max-parallelism=256 -oG - | awk '/Up$/{print $2}' > live_hosts.txt")
    else:
        os.system("nmap -iL inputlist.txt -6 -T5 -n -sn --min-parallelism=100 --max-parallelism=256 -oG - | awk '/Up$/{print $2}' > live_hosts.txt")

    print('Live Host scan done ...')

    with open("live_hosts.txt") as f:
        hostlist = f.readlines()
    hostlist = [x.strip() for x in hostlist]

    os.remove(ipfile)
    os.remove('live_hosts.txt')

    return hostlist


def general_service_discovery(live_hosts, outfile, ip_type):
    """
        live_hosts: Live hosts found with the host discovery
        outfile:    The original input file given as a parameter when starting the script
        ip_type:    Type of IP address used.

        Function:
        Attempts to find services on hosts and save it in XML format to outfile

        Return value:
        Outfile object
        """

    print('Starting Service Discovery process ...')

    fp = open("host_for_general_scan.txt", "w")
    for host in live_hosts:
        fp.write(host + '\n')
    fp.close()

    if ip_type == 'ipv4':
        os.system("nmap -iL host_for_general_scan.txt -T5 -sV --min-parallelism=100 --max-parallelism=256 -oX " + outfile.name)
    else:
        os.system("nmap -iL host_for_general_scan.txt -6 -T5 -sV --min-parallelism=100 --max-parallelism=256 -oX " + outfile.name)

    print('Service scan done ...')
    os.remove("host_for_general_scan.txt")

    return outfile


def shuffle_data(inputfile):
    """
        inputfile:  The original input file given as a parameter when starting the script
\
        Function:
        Shuffles rows around to prevent the scanning of a whole institution at once

        Return value:
        Name of file where ip records are shuffled
        """
    print('Shuffle IP addresses ...')
    fid = open(inputfile, "r")
    li = fid.readlines()
    fid.close()

    random.shuffle(li)

    fid = open(inputfile + '_shuffled', "w")
    fid.writelines(li)
    fid.close()
    return inputfile + '_shuffled'


def combine_ip_port(inputfile, hosts, ip_type):
    """
    inputfile:  The original input file given as a parameter when starting the script
    hosts:      Live hosts found with the host discovery
    ip_type:    Type of IP address used.

    Function:
    Will combine the live hosts with the input file to create a list where live hosts are combined
    with the "live" service ports.

    Return value:
    list of live hosts with ports
    """

    hosts_and_ports = []
    with open(inputfile, "r") as file:
        if ip_type == 'ipv4':
            fp = csv.reader(file, delimiter=':')
        else:
            fp = csv.reader(file, delimiter='.')
        for row in fp:
            for field in row:
                if field in hosts:
                    hosts_and_ports.append(row)
    return hosts_and_ports


def main(arguments):

    """
    Input files should be structured like this:
    IPv4 files : ip:port        extension : .ipv4
    IPv6 files : ip.port        extension : .ipv6
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', help='Input file', action=check_ext({'ipv4', 'ipv6'}))
    parser.add_argument("outfile", help="Output file", type=argparse.FileType("w"))
    parser.add_argument("ip_type", choices=['ipv4', 'ipv6'])

# Convert args to usable variables
    args = parser.parse_args(arguments)
    infile = args.infile
    outfile = args.outfile
    ip_type = args.ip_type

    shuf_file = shuffle_data(infile)
    datafile = split_data(shuf_file, ip_type)
    live_hosts = live_host_check(datafile, ip_type)

    # This is only needed for targeted scan, which at this point is not implemented yet.
    #ip_port_list = combine_ip_port(infile, live_hosts, ip_type)

    general_service_discovery(live_hosts, outfile, ip_type)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
