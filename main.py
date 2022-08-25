import json
import sys


def read_json_file(json_file_name):
    with open(json_file_name, "r") as json_file:
        data = json.load(json_file)
        return data

def is_owasp_scan(json_data):
    return isinstance(json_data, dict) and "projectInfo" in json_data.keys() and "dependencies" in json_data.keys()

def is_xray_scan(json_data):
    return isinstance(json_data, dict) and "vulnerabilities" in json_data.keys()

def get_owasp_cves(json_data):
    for dependency in json_data["dependencies"]:
        if "vulnerabilities" in dependency.keys():
            for package in dependency["packages"]:
                pkg_id = package["id"].split("/")
                pkg_name = pkg_id[1] +":"+ pkg_id[2]
                print(f'{pkg_name}')

def get_xray_cves(json_data):
    for vulnerability in json_data["vulnerabilities"]:
        pkg_name = vulnerability["impactedPackageName"] +"@"+ vulnerability["impactedPackageVersion"]
        print(f'{pkg_name}')

def get_package_cves(json_data):
    if is_owasp_scan(json_data):
        get_owasp_cves(json_data)
    if is_xray_scan(json_data):
        get_xray_cves(json_data)

def get_file_cves(json_file):
    json_data = read_json_file(json_file)
    return get_package_cves(json_data)

def diff_files(json_file_name1, json_file_name2):
    print(f'\nreport {json_file_name1}\n')
    json_data1 = get_file_cves(json_file_name1)
    print(f'\nreport {json_file_name2}\n')
    json_data2 = get_file_cves(json_file_name2)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage:\n{sys.argv[0]} report1.json report2.json')
        sys.exit(1)

    diff_files(sys.argv[1], sys.argv[2])
