from Class.VirusTotal import VirusTotal
import json

vt = VirusTotal("cfd5ccd2dce4a3e5ca5bb9d7a52889bce569d229854779d26fac048d1a386a01")

# vt.url("pplware.sapo.pt")
# vt.scan_url()
# print(json.dumps(vt.scan_url_report(), indent=2))

print("----------------------------")

vt.file("_config.yml")
vt.scan_file()
print(json.dumps(vt.scan_file_report(), indent=2))