#!/usr/bin/python3

import os
import argparse

from loguru import logger
from pathlib import Path
from magika import Magika
from typing import Literal, Set

from mgtool import Scanner, Extractor


class Operation:

    def __init__(self):
        self.scanned_file_path_set = set()

    def scan_image_by_path(self, path: Path, rules: Set[str], manufacturer: str, product: str, version: str, endian: Literal["little", "big"] = "little", debug: bool = True):
        m = Magika()
        fw_path = str(path)
        with Extractor(fw_path=fw_path, endian=endian, target="root", fw_info={"manufacturer": manufacturer.lower(), "product": product.lower(), "version": version.lower()}, debug=debug) as extractor:
            for root, _, files in os.walk(extractor.OutDir):
                for name in files:
                    file_path = os.path.realpath(os.path.join(root, name))
                    if os.path.islink(file_path):
                        continue
                    if not os.path.isfile(file_path):
                        continue
                    if "CVE-2023-34335" in rules:
                        self.scan_cve_2023_34335_by_path(file_path, magic=m, debug=debug)
        # TODO: add passwd check

    def scan_cve_2023_34335_by_path(self, file_path: str, magic: Magika, debug: bool = True):
        if magic.identify_path(Path(file_path)).output.ct_label not in ["so", "elf"]:
            return
        if "libipmipdkcmds.so" not in str(file_path) and "libipmimsghndlr.so" not in str(file_path):
            return
        with open(file_path, "rb") as f:
            # logger.info(f"scan {file_path}")
            if b"_MsgHndlrTbl\0" in f.read():
                logger.info(f"scan {file_path}")
                if file_path in self.scanned_file_path_set:
                    return
                self.scanned_file_path_set.add(file_path)
                with Scanner(bin_path=Path(file_path), rule_name_set={"CVE-2023-34335"}, debug=debug) as s:
                    s.batch_scan()


parser = argparse.ArgumentParser("BMC FwSpy Nano")
parser.add_argument("--path", type=str, required=True)
parser.add_argument("--actions", type=str, choices=['display', 'cosflash', 'passwd'], nargs='+', default=['display'])
parser.add_argument("--endian", type=str, choices=['little', 'big'], default='little')
parser.add_argument("--manufacturer", type=str, required=True)
parser.add_argument("--product", type=str, required=True)
parser.add_argument("--version", type=str, required=True)
parser.add_argument("--debug", action="store_true")
args = parser.parse_args()


if __name__ == "__main__":
    Operation().scan_image_by_path(Path(args.path), args.actions, args.manufacturer, args.product, args.version, args.endian, args.debug)
