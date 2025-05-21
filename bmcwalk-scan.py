#!/usr/bin/python3

import argparse

from pathlib import Path

from bmcwalk import Operator


# class Operation:
#
#     def __init__(self):
#         self.scanned_file_path_set = set()
#         self.magic = Magika()
#
#     def scan_image_by_path(self, path: Path, rules: Set[str], manufacturer: str, product: str, version: str, endian: Literal["little", "big"] = "little", debug: bool = True):
#         fw_path = str(path)
#         with Extractor(fw_path=fw_path, endian=endian, target="root", fw_info={"manufacturer": manufacturer.lower(), "product": product.lower(), "version": version.lower()}, debug=debug) as extractor:
#             for root, _, files in os.walk(extractor.OutDir):
#                 for name in files:
#                     file_path = os.path.realpath(os.path.join(root, name))
#                     if os.path.islink(file_path):
#                         continue
#                     if not os.path.isfile(file_path):
#                         continue
#                     if "CVE-2023-34335" in rules:
#                         self.scan_cve_2023_34335_by_path(file_path, debug=debug)
#                     if "CVE-2023-34342" in rules:
#                         self.scan_cve_2023_34342_by_path(file_path, debug=debug)
#                     if "CVE-2025-23016" in rules:
#                         self.scan_cve_2025_23016_by_path(file_path, debug=debug)
#         # TODO: add passwd check
#
#     def scan_cve_2025_23016_by_path(self, file_path: str, debug: bool = True):
#         if self.magic.identify_path(Path(file_path)).output.ct_label not in ["so", "elf"]:
#             return
#         if "/libfcgi.so" not in file_path:
#             return
#         if file_path in self.scanned_file_path_set:
#             return
#         self.scanned_file_path_set.add(file_path)
#         with Scanner(bin_path=Path(file_path), rule_name_set={"CVE-2025-23016"}, debug=debug) as s:
#             batch_result = s.batch_scan()
#             if "CVE-2025-23016" not in batch_result.keys():
#                 return
#             if "CVE-2025-23016-vuln" not in batch_result["CVE-2025-23016"].keys():
#                 return
#             if len(batch_result["CVE-2025-23016"]["CVE-2025-23016-vuln"]) >= 1:
#                 logger.error("CVE-2025-23016: Vulnerable")
#
#     def scan_cve_2023_34342_by_path(self, file_path: str, debug: bool = True):
#         if self.magic.identify_path(Path(file_path)).output.ct_label not in ["so", "elf"]:
#             return
#         if "/libipmimsghndlr.so" not in file_path:
#             return
#         if file_path in self.scanned_file_path_set:
#             return
#         self.scanned_file_path_set.add(file_path)
#         with Scanner(bin_path=Path(file_path), rule_name_set={"CVE-2023-34342"}, debug=debug) as s:
#             batch_result = s.batch_scan()
#             if "CVE-2023-34342" not in batch_result.keys():
#                 return
#             if "CVE-2023-34342-vuln" not in batch_result["CVE-2023-34342"].keys():
#                 return
#             if len(batch_result["CVE-2023-34342"]["CVE-2023-34342-vuln"]) >= 1:
#                 logger.error("CVE-2023-34342: Vulnerable")
#
#     def scan_cve_2023_34335_by_path(self, file_path: str, debug: bool = True):
#         if self.magic.identify_path(Path(file_path)).output.ct_label not in ["so", "elf"]:
#             return
#         if "/libipmipdkcmds.so" not in file_path and "/libipmimsghndlr.so" not in file_path:
#             return
#         logger.info(f"scanning {file_path}")
#         with open(file_path, "rb") as f:
#             # logger.info(f"scan {file_path}")
#             if b"_MsgHndlrTbl\0" in f.read():
#                 logger.info(f"scan {file_path}")
#                 if file_path in self.scanned_file_path_set:
#                     return
#                 self.scanned_file_path_set.add(file_path)
#                 with Scanner(bin_path=Path(file_path), rule_name_set={"CVE-2023-34335"}, debug=debug) as s:
#                     print(s.batch_scan())
#
#     def scan_cve_2018_25103_by_path(self, file_path: str, magic: Magika, debug: bool = True):
#         if magic.identify_path(Path(file_path)).output.ct_label not in ["so", "elf"]:
#             return
#         if "/usr/local/sbin/lighttpd" not in str(file_path):
#             return
#         if file_path in self.scanned_file_path_set:
#             return
#         self.scanned_file_path_set.add(file_path)
#         with Scanner(bin_path=Path(file_path), rule_name_set={"CVE-2018-25103"}, debug=debug) as s:
#             print(s.batch_scan())


parser = argparse.ArgumentParser("BMC FwSpy Nano")
parser.add_argument("--path", type=str, required=True)
parser.add_argument("--rules", type=str, choices=['CVE-2025-23016', 'CVE-2023-34335', 'CVE-2023-34342', 'CVE-2018-25103', 'weak-password'], nargs='+', default=['CVE-2023-34335'])
parser.add_argument("--endian", type=str, choices=['little', 'big'], default='little')
parser.add_argument("--manufacturer", type=str, required=True)
parser.add_argument("--product", type=str, required=True)
parser.add_argument("--version", type=str, required=True)
parser.add_argument("--debug", action="store_true")
args = parser.parse_args()

banner = '''
 _______   ___      ___   ______   __   __  ___       __      ___       __   ___  
|   _  "\\ |"  \\    /"  | /" _  "\\ |"  |/  \\|  "|     /""\\    |"  |     |/"| /  ") 
(. |_)  :) \\   \\  //   |(: ( \\___)|'  /    \\:  |    /    \\   ||  |     (: |/   /  
|:     \\/  /\\   \\/.    | \\/ \\     |: /'        |   /' /\\  \\  |:  |     |    __/   
(|  _  \\\\ |: \\.        | //  \\ _   \\//  /\\'    |  //  __'  \\  \\  |___  (// _  \\   
|: |_)  :)|.  \\    /:  |(:   _) \\  /   /  \\\\   | /   /  \\\\  \\( \\_|:  \\ |: | \\  \\  
(_______/ |___|\\__/|___| \\_______)|___/    \\___|(___/    \\___)\\_______)(__|  \\__) 
                                                                                  
'''


if __name__ == "__main__":
    print(banner)
    op = Operator(debug=args.debug)
    op.scan_image_by_fw_path(Path(args.path), set(args.rules), args.manufacturer, args.product, args.version, args.endian, args.debug)
