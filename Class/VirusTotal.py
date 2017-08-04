import requests

class VirusTotal:
    __key=""

    def __init__(self,key):
        self.__key= key

    def set_key(self,key):
        self.__key = key

    def scan_file(self,files):
        params = {'apikey': self.__key}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        return response.json()

    def rescan_file(self,files):
        params = {'apikey': self.__key, 'resource': '7657fcb7d772448a6d8504e4b20168b8'}
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',
                                 params=params)
        json_response = response.json()

