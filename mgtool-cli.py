#!/usr/bin/python3

import os
import argparse

from loguru import logger
from pathlib import Path
from magika import Magika
from typing import Literal, List

from mgtool import AnalysisIpmiLib, Extractor


def scan_image_by_path(path: Path, actions: List[str], manufacturer: str, product: str, version: str, endian: Literal["little", "big"] = "little", debug: bool = True):
    m = Magika()
    fw_path = str(path)
    if len(set(actions) & set({"display", "cosflash"})) > 0:
        with Extractor(fw_path=fw_path, endian=endian, target="root", fw_info={"manufacturer": manufacturer.lower(), "product": product.lower(), "version": version.lower()}, debug=debug) as extractor:
            scanned_file_path_set = set()
            for root, _, files in os.walk(extractor.OutDir):
                for name in files:
                    file_path = os.path.realpath(os.path.join(root, name))
                    if os.path.islink(file_path):
                        continue
                    if not os.path.isfile(file_path):
                        continue
                    if ".so." not in file_path:
                        continue
                    if m.identify_path(Path(file_path)).output.ct_label not in ["so", "elf"]:
                        continue
                    with open(file_path, "rb") as f:
                        # logger.info(f"scan {file_path}")
                        if b"_MsgHndlrTbl\0" in f.read():
                            logger.info(f"scan {file_path}")
                            if file_path in scanned_file_path_set:
                                continue
                            scanned_file_path_set.add(file_path)
                            with AnalysisIpmiLib(ipmi_lib_path=Path(file_path), debug=debug) as analyzer:
                                curr_actions = set(actions) & set({"display", "cosflash"})
                                analyzer.do(curr_actions)
    # TODO: add passwd check


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
    scan_image_by_path(Path(args.path), args.actions, args.manufacturer, args.product, args.version, args.endian, args.debug)
