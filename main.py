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


def is_xray_docker_scan(json_data: list) -> bool:
    return isinstance(json_data, list) and len(json_data) > 0 \
           and isinstance(json_data[0], dict) and "vulnerabilities" in json_data[0].keys()


def get_component(components: list, component_name: str) -> dict:
    for component in components:
        if component["name"] == component_name:
            return component
    return None


def has_vul(pkg_vuls, vul_name):
    for pkg_vul in pkg_vuls:
        if pkg_vul["name"] == vul_name:
            return True
    return False


def get_vulnerability_sort_key(v: dict):
    return v["name"]


def get_component_sort_key(c: dict):
    return c["name"]


def get_owasp_components(json_data: dict):
    components = []
    for dependency in json_data["dependencies"]:
        if "vulnerabilities" in dependency.keys():
            for package in dependency["packages"]:
                id = package["id"].split("/")
                package_name = id[1] + ":" + id[2]
                component = get_component(components, package_name)
                if component is None:
                    component = {"name": package_name, "vulnerabilities": []}
                    components.append(component)
                    components.sort(key=get_component_sort_key)
                for vul in dependency["vulnerabilities"]:
                    component_vulnerabilities = component["vulnerabilities"]
                    cve_id = vul["name"]
                    if len(cve_id) > 0 and not has_vul(component_vulnerabilities, cve_id):
                        component_vulnerabilities.append({"name": cve_id})
                        component_vulnerabilities.sort(key=get_vulnerability_sort_key)
    return components


def get_xray_components(json_data: dict):
    components = []
    for vul in json_data["vulnerabilities"]:
        package_name = vul["impactedPackageName"] + "@" + vul["impactedPackageVersion"]
        component = get_component(components, package_name)
        if component is None:
            component = {"name": package_name, "vulnerabilities": []}
            components.append(component)
            components.sort(key=get_component_sort_key)
        if "cves" in vul.keys():
            component_vulnerabilities = component["vulnerabilities"]
            for cve in vul["cves"]:
                cve_id = cve["id"]
                if len(cve_id) > 0 and not has_vul(component_vulnerabilities, cve_id):
                    component_vulnerabilities.append({"name": cve_id})
                    component_vulnerabilities.sort(key=get_vulnerability_sort_key)
    return components


def get_component_name(orig_name: str) -> str:
    name = orig_name
    if orig_name.startswith("gav://"):
        component = orig_name.split("/")[2].split(":")
        name = component[0] + ":" + component[1] +"@"+ component[2]
    elif orig_name.startswith("pypi://"):
        component = orig_name.split("/")[2].split(":")
        name = component[0] + "@" + component[1]
    return name


def get_xray_docker_components(json_data: list):
    components = []
    scan = json_data[0]
    if "vulnerabilities" in scan.keys():
        for vulnerability in scan["vulnerabilities"]:
            for vul_comp_name in vulnerability["components"].keys():
                component_name = get_component_name(vul_comp_name)
                component = get_component(components, component_name)
                if component is None:
                    component = {"name": component_name, "vulnerabilities": []}
                    components.append(component)
                    components.sort(key=get_component_sort_key)
                if "cves" in vulnerability.keys():
                    component_vulnerabilities = component["vulnerabilities"]
                    for cve in vulnerability["cves"]:
                        if "cve" in cve.keys():
                            cve_id = cve["cve"]
                            if len(cve_id) > 0 and not has_vul(component_vulnerabilities, cve_id):
                                component_vulnerabilities.append({"name": cve_id})
                                component_vulnerabilities.sort(key=get_vulnerability_sort_key)
    return components


def get_components(json_data):
    componentss = []
    if is_owasp_scan(json_data):
        print(f'is_owasp_scan')
        componentss = get_owasp_components(json_data)
    elif is_xray_scan(json_data):
        print(f'is_xray_scan')
        componentss = get_xray_components(json_data)
    elif is_xray_docker_scan(json_data):
        print(f'is_xray_docker_scan')
        componentss = get_xray_docker_components(json_data)
    else:
        print(f'unknown data')
    return componentss


def get_file_components(json_file):
    json_data = read_json_file(json_file)
    return get_components(json_data)


def diff_files(json_file_name1: str, json_file_name2: str, report_renderer: ReportRenderer):
    print(f'report {json_file_name1}')
    comps1 = get_file_components(json_file_name1)
    print(f'{comps1}\n')
    print(f'report {json_file_name2}')
    comps2 = get_file_components(json_file_name2)
    print(f'{comps2}\n')

    report_renderer.render_header(json_file_name1, json_file_name2)

    i1 = 0
    i2 = 0

    while i1 < len(comps1):

        while i2 < len(comps2) and comps1[i1]["name"] > comps2[i2]["name"]:
            report_renderer.render_row(None, comps2[i2])
            i2 += 1

        column1 = comps1[i1]
        column2 = None

        if i2 < len(comps2) and comps1[i1]["name"] == comps2[i2]["name"]:
            column2 = comps2[i2]
            i2 += 1

        report_renderer.render_row(column1, column2)

        i1 += 1

    while i2 < len(comps2):
        report_renderer.render_row(None, comps2[i2])
        i2 += 1

    report_renderer.render_footer()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f'Usage:\n{sys.argv[0]} report1.json report2.json')
        sys.exit(1)

    output_file = "cves-diff-out.md" if len(sys.argv) < 4 else sys.argv[3]

    with open(output_file, 'w') as f:
        diff_files(sys.argv[1], sys.argv[2], MarkDownRenderer(f))
