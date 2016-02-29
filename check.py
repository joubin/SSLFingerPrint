#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from lxml import html
import requests
import os

""" EV checks not fully working yet"""


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SSLChecker:
    def __init__(self):
        self.user_home = os.path.expanduser('~')
        self.config_dir = os.path.join(self.user_home, ".sslchecker")
        self.config_file = os.path.join(self.config_dir, "conf")
        self.verification_server_property = "verification_server"
        self.verification_server = ""
        self.verification_user_property = "verification_user"
        self.verification_user = ""
        self.authentication_property = "authentication"
        self.authentication = ""
        self.path_to_ssh_key_property = "path_to_ssh_key"
        self.path_to_ssh_key = ""
        self.remote_connection_command = ""
        self.read_config()

    def get_oids(self):
        page = requests.get(
            "https://en.wikipedia.org/wiki/Extended_Validation_Certificate#Extended_Validation_certificate_identification")
        tree = html.fromstring(page.text)

        items = tree.xpath("//*[@id=\"mw-content-text\"]/table[2]")
        dictionary = {}
        for i in items:
            for x in i:
                try:
                    dictionary[x[0].text_content()] = x[1].text_content()
                except KeyError as ignore:
                    dictionary[x[0].text_content()] = [x[1].text_content()]

        clean = {}
        for k in dictionary.keys():
            clean[k] = dictionary[k].split()

        return clean

    def mix_oids(self):
        oids = ["1.3.6.1.4.1.34697.2.1", "1.3.6.1.4.1.34697.2.2", "1.3.6.1.4.1.34697.2.1 ", "1.3.6.1.4.1.34697.2.3 ",
                "1.3.6.1.4.1.34697.2.4", "1.2.40.0.17.1.22", "2.16.578.1.26.1.3.3", "1.3.6.1.4.1.17326.10.14.2.1.2 ",
                "1.3.6.1.4.1.17326.10.8.12.1.2", "1.3.6.1.4.1.6449.1.2.1.5.1", "2.16.840.1.114412.2.1",
                "2.16.528.1.1001.1.1.1.12.6.1.1.1", "2.16.840.1.114028.10.1.2", "1.3.6.1.4.1.14370.1.6",
                "1.3.6.1.4.1.4146.1.1", "2.16.840.1.114413.1.7.23.3", "1.3.6.1.4.1.14777.6.1.1 ",
                "1.3.6.1.4.1.14777.6.1.2",
                "1.3.6.1.4.1.22234.2.5.2.3.1", "1.3.6.1.4.1.782.1.2.1.8.1", "1.3.6.1.4.1.8024.0.2.100.1.2",
                "1.2.392.200091.100.721.1", "2.16.840.1.114414.1.7.23.3", "1.3.6.1.4.1.23223.2 ",
                "1.3.6.1.4.1.23223.1.1.1 ", "1.3.6.1.5.5.7.1.1", "2.16.756.1.89.1.2.1.1", "2.16.840.1.113733.1.7.48.1",
                "2.16.840.1.114404.1.1.2.4.1", "2.16.840.1.113733.1.7.23.6", "1.3.6.1.4.1.6334.1.100.1",
                "1.3.6.1.4.1.11129.2.5.1"]
        wiki = self.get_oids()
        wiki = list(self.flatten(wiki.values()))
        [oids.append(x) for x in wiki if x not in oids]
        oids = list(oids)
        return oids

    # noinspection PyTypeChecker
    def get_ev_policy(self, server_to_check):
        """
        Uses https://tools.ietf.org/html/rfc5280#page-110 to find the OID
        https://tools.ietf.org/html/rfc5280#appendix-A
        :param server_to_check: uses openssl to connect to the server.
                This open ssl call is via the OS's default commandline
                so that the same code could be executed over ssh
        :return:
        """
        full_cert_command = "echo | openssl s_client -connect " + server_to_check + ":443 2>&1 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout "
        output = os.popen(full_cert_command).read()
        unclean_break = output.split('\n')

        oid = ""
        issuer = ""
        for line in unclean_break:
            if "policy" in line.lower():
                oid = line.split(':')[1].strip()
            if "issuer" in line.lower() and "o=" in line.lower():
                for x in line.split(':')[1].strip().split(","):
                    if "O=" in x:
                        issuer = x.split("=")[1]
        return oid, issuer

    def is_cert_ev(self, oid):
        oids = self.mix_oids()

        for idVal in oids:
            if oid in idVal:
                return True
        return False

    def get_fingerprint(self, server_to_check):
        fingerprint_command = "echo R |openssl s_client -connect " + server_to_check + ":443 2>/dev/null| sed -ne " \
                                                                                       "'/-BEGIN CERTIFICATE-/,/-END " \
                                                                                       "CERTIFICATE-/p' 2> " \
                                                                                       "/dev/null | " \
                                                                                       "openssl x509 -noout -in " \
                                                                                       "/dev/stdin -fingerprint -sha1"
        remote_command = self.remote_connection_command + ' "' + fingerprint_command + '" 2> /dev/null'

        return os.popen(fingerprint_command).read(), os.popen(remote_command).read()

    def does_fingerprint_match(self, server_to_check):
        result = self.get_fingerprint(server_to_check)
        print("Local: " + str(result[0].strip('\n')))
        print("Remote: " + str(result[1].strip('\n')))
        if result[0] == result[1]:
            return True
        return False

    def create_conf(self, should_create_conf=True, create_conf_dir=False):
        if create_conf_dir:
            os.mkdir(self.config_dir)
        if should_create_conf:
            with open(self.config_file, mode="w") as file:
                file.write(self.verification_server_property + ":example.com\n")
                file.write(self.verification_user_property + ":john\n")
                file.write("# Comment the following line out if you have ssh keys\n")
                file.write("# This is not really safe \n")
                file.write(self.authentication_property + ":password\n")
                # file.write("#"+self.authentication_property+":key\n")
                # file.write(self.path_to_ssh_key_property+":~/.ssh/id_rsa\n")
                file.flush()
            print("The configuration file didn't exist. I've made you one at: " + self.config_file)
            print("Please edit it")

    def read_config(self):
        if not os.path.isdir(self.config_dir):
            self.create_conf(True, True)
        else:
            if os.path.exists(self.config_file):
                pass
            else:
                self.create_conf()

        with open(self.config_file, mode='r') as conf:
            for i in conf:
                if "#" in i:
                    pass
                else:
                    tmp = i.strip('\n').split(':')
                    property_str = tmp[0]
                    property_value = tmp[1]
                    if property_str == self.verification_server_property:
                        self.verification_server = property_value
                    elif property_str == self.verification_user_property:
                        self.verification_user = property_value
                    elif property_str == self.authentication_property:
                        self.authentication = property_value
        self.create_remote_connection_command()

    @staticmethod
    def flatten(listoflist):
        """Flatten one level of nesting"""
        result = []

        def flatten_recursive(sublist):
            if type(sublist) != list:
                result.append(sublist)
                return
            for item in sublist:
                if type(item) != list:
                    result.append(item)
                else:
                    flatten_recursive(item)

        for item in listoflist:
            flatten_recursive(item)
        return result

    def create_remote_connection_command(self):
        if self.authentication == "":
            self.remote_connection_command = 'typeset -f | ssh -o ConnectTimeout=10 -t {0}@{1}'.format(
                self.verification_user, self.verification_server)
        else:
            self.remote_connection_command = 'typeset -f | sshpass -p \'{0}\' ssh -o ConnectTimeout=10 -t  {1}@{2}'.format(
                self.authentication, self.verification_user, self.verification_server)

    def run_check(self, server_to_check):
        print("Checking: {0}".format(server_to_check))
        if checker.does_fingerprint_match(server_to_check):
            print(bcolors.OKGREEN + "Finger print matched. This means you're safe\n" + bcolors.ENDC)
        else:
            print(bcolors.WARNING + "Finger print did NOT match. This could be a problem.\n"
                  "One exception is that distributed servers could have more than once certificate.\n"
                  "Which results in multiple certificates" + bcolors.ENDC)


if __name__ == '__main__':
    server = ""
    try:
        server = sys.argv[1]
        checker = SSLChecker()
        checker.run_check(server)
    except IndexError:
        print("Please provide a server to check\n"
              "eg:\t{0} example.com".format(sys.argv[0]))
