import json
import sys


class ReportRenderer:
    def render_header(self, head1: str, head2: str):
        pass

    def render_row(self, column1: str, column2: str):
        pass

    def render_footer(self):
        pass


class MarkDownRenderer(ReportRenderer):
    def __init__(self, out):
        self.out = out

    def render_header(self, head1: str, head2: str):
        self.out.write(f'| {head1} | {head2} |\n')
        self.out.write('| --- | --- |\n')

    def __column_value(self, column: dict) -> str:
        column_str = ''
        if column is not None:
            column_str += column["name"]
            if column["vulnerabilities"] and len(column["vulnerabilities"]) > 0:
                column_str += "<br/>"
                column_str += "<br/>".join(v["name"] for v in column["vulnerabilities"])
        return column_str

    def render_row(self, column1: dict, column2: dict):
        self.out.write(f'| {self.__column_value(column1)} | {self.__column_value(column2)} |\n')

    def render_footer(self):
        pass


def read_json_file(json_file_name: str) -> dict:
    with open(json_file_name, "r") as json_file:
        data = json.load(json_file)
        return data


def is_owasp_scan(json_data: dict) -> bool:
    return isinstance(json_data, dict) and "projectInfo" in json_data.keys() and "dependencies" in json_data.keys()


def is_xray_scan(json_data: dict) -> bool:
    return isinstance(json_data, dict) and "vulnerabilities" in json_data.keys()


def get_package(packages: list, pkg_name: str) -> dict:
    for package in packages:
        if package["name"] == pkg_name:
            return package
    return None


def has_vul(pkg_vuls, vul_name):
    for pkg_vul in pkg_vuls:
        if pkg_vul["name"] == vul_name:
            return True
    return False


def get_vul_sort_key(vul: dict):
    return vul["name"]


def get_pkg_sort_key(pkg: dict):
    return pkg["name"]


def get_owasp_packages(json_data: dict):
    packages = []
    for dep in json_data["dependencies"]:
        if "vulnerabilities" in dep.keys():
            for pkg in dep["packages"]:
                id = pkg["id"].split("/")
                package_name = id[1] + ":" + id[2]
                package = get_package(packages, package_name)
                if package is None:
                    package = {"name": package_name, "vulnerabilities": []}
                    packages.append(package)
                    packages.sort(key=get_pkg_sort_key)
                for vul in dep["vulnerabilities"]:
                    pkg_vuls = package["vulnerabilities"]
                    if not has_vul(pkg_vuls, vul["name"]):
                        pkg_vuls.append({"name": vul["name"]})
                        pkg_vuls.sort(key=get_vul_sort_key)
    return packages


def get_xray_packages(json_data: dict):
    packages = []
    for vul in json_data["vulnerabilities"]:
        package_name = vul["impactedPackageName"] + "@" + vul["impactedPackageVersion"]
        package = get_package(packages, package_name)
        if package is None:
            package = {"name": package_name, "vulnerabilities": []}
            packages.append(package)
            packages.sort(key=get_pkg_sort_key)
        if "cves" in vul.keys():
            pkg_vuls = package["vulnerabilities"]
            for cve in vul["cves"]:
                cve_id = cve["id"]
                if not has_vul(pkg_vuls, cve_id):
                    pkg_vuls.append({"name": cve_id})
                    pkg_vuls.sort(key=get_vul_sort_key)
    return packages


def get_packages(json_data: dict):
    packages = []
    if is_owasp_scan(json_data):
        packages = get_owasp_packages(json_data)
    if is_xray_scan(json_data):
        packages = get_xray_packages(json_data)
    return packages


def get_file_packages(json_file: dict):
    json_data = read_json_file(json_file)
    return get_packages(json_data)


def diff_files(json_file_name1: str, json_file_name2: str, report_renderer: ReportRenderer):
    print(f'\nreport {json_file_name1}\n')
    pkgs1 = get_file_packages(json_file_name1)
    print(f'{pkgs1}\n')
    print(f'\nreport {json_file_name2}\n')
    pkgs2 = get_file_packages(json_file_name2)
    print(f'{pkgs2}\n')

    report_renderer.render_header(json_file_name1, json_file_name2)

    i1 = 0
    i2 = 0

    while i1 < len(pkgs1):

        while i2 < len(pkgs2) and pkgs1[i1]["name"] > pkgs2[i2]["name"]:
            report_renderer.render_row(None, pkgs2[i2])
            i2 += 1

        column1 = pkgs1[i1]
        column2 = None

        if i2 < len(pkgs2) and pkgs1[i1]["name"] == pkgs2[i2]["name"]:
            column2 = pkgs2[i2]
            i2 += 1

        report_renderer.render_row(column1, column2)

        i1 += 1

    while i2 < len(pkgs2):
        report_renderer.render_row(None, pkgs2[i2])
        i2 += 1

    report_renderer.render_footer()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage:\n{sys.argv[0]} report1.json report2.json')
        sys.exit(1)

    output_file = "cves-diff-out.md" if len(sys.argv) < 4 else sys.argv[3]

    with open(output_file, 'w') as f:
        diff_files(sys.argv[1], sys.argv[2], MarkDownRenderer(f))
