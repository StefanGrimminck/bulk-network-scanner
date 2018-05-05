import argparse
import sys
import os
import csv
import random

def check_ext(choices):
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

    datafile = "inputlist.txt"

    with open(inputfile_shuf, 'r') as csvfile:
        if ip_type == 'ipv4':
            fp = csv.reader(csvfile, delimiter=':')
        else:
            fp = csv.reader(csvfile, delimiter='.')

        for row in fp:
            with open(datafile, "a") as myfile:
                myfile.write(row[0] + '\n')

    os.remove(inputfile_shuf)

    return datafile

def live_host_check(ipfile, ip_type):
    print('Starting Nmap subprocess ...')

    if ip_type == 'ipv4':
        os.system("nmap -iL inputlist.txt -T5 -n -sn --min-parallelism=100 --max-parallelism=256 -oG - | awk '/Up$/{print $2}' > live_hosts.txt")
    else:
        #Needs to be tested for IPv6 output format
        os.system("nmap -iL inputlist.txt -6 -T5 -n -sn --min-parallelism=100 --max-parallelism=256 -oG - | awk '/Up$/{print $2}' > live_hosts.txt")

    print('Live Host scan done ...')

    with open("live_hosts.txt") as f:
        content = f.readlines()
    content = [x.strip() for x in content]

    os.remove(ipfile)
    os.remove('live_hosts.txt')

    return content



def shuffle_data(inputfile):
    print('Randomzing IP address order...')
    fid = open(inputfile, "r")
    li = fid.readlines()
    fid.close()

    random.shuffle(li)

    fid = open(inputfile + '_shuffled', "w")
    fid.writelines(li)
    fid.close()
    return inputfile + '_shuffled'


def main(arguments):

    """
    This script is created for scanning IPv4 and IPv6 addresses.
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

    shuf_file  = shuffle_data(infile)
    datafile   = split_data(shuf_file, ip_type)
    live_hosts = live_host_check(datafile, ip_type)

    # TEMPORARY OUTPUT FOR DEBUGGING #
    fp = open(outfile.name, "w")
    for host in live_hosts:
        fp.write(host + '\n')
    fp.close()



if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
