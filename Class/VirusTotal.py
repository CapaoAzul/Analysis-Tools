import requests
import json
import hashlib

from Class.Tool import Tool


class VirusTotal(Tool):
    __file = None
    __url = None

    def __init__(self, key):
        super(VirusTotal, self).__init__(key)

    def url(self, url):
        self.__url = url

    def file(self, file):
        self.__file = file

    def scan_file(self):
        params = {'apikey': self.get_key()}
        files = {'file': (self.get_file(), open(self.get_file(), 'rb'))}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        return response.json()

    def rescan_file(self):
        # Calculate hash file
        hasher = hashlib.md5()
        with open(self.get_file(), 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        hash_file = hasher.hexdigest()

        # Make the request to VirusTotal
        params = {'apikey': self.get_key(), 'resource': hash_file}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  Analysis-Tools"
        }
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',
                                 params=params)
        return response.json()

    def scan_file_report(self):
        # Calculate hash file
        hasher = hashlib.md5()
        with open(self.get_file(), 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        hash_file = hasher.hexdigest()

        # Make the request to VirusTotal
        params = {'apikey': self.get_key(), 'resource': hash_file}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  Analysis-Tools"
        }
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/report',
                                 params=params)
        return response.json()

    def scan_url(self):
        params = {'apikey': self.get_key(), 'url': self.get_url()}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        return response.json()

    def scan_url_report(self):
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,   Analysis-Tools"
        }
        params = {'apikey': self.get_key(), 'resource': self.get_url()}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                                 params=params, headers=headers)
        return response.json()

    def get_url(self):
        return self.__url

    def get_file(self):
        return self.__file








