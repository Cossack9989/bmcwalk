import os
import re
import yaml

from loguru import logger
from pathlib import Path
from magika import Magika
from typing import Literal, Set, Optional

from bmcwalk.extractor import Extractor
from bmcwalk.scanner import Scanner


class Operator:

    def __init__(self, debug: bool = False, bmc_type: Optional[Literal["MegaRAC", "OpenBMC"]] = None):
        self.scanned_file_path_map = dict()
        self.magic = Magika()
        self.debug = debug
        self_dirt = os.path.dirname(__file__)
        self.rule_dirt = os.path.join(self_dirt, "rules")
        self.bmc_type = bmc_type
        self.report = dict()

    def scan_image_by_fw_path(self, path: Path, rule_name_set: Set[str], manufacturer: str, product: str, version: str, endian: Literal["little", "big"] = "little", debug: bool = True):
        fw_path = str(path)
        for rule_name in rule_name_set:
            self.scanned_file_path_map[rule_name] = set()
            rule_path = os.path.join(self.rule_dirt, f"{rule_name}.yml")
            with open(rule_path) as rule_stream:
                rule: dict = yaml.safe_load(rule_stream)
                target = rule["target"]
                with Extractor(fw_path=fw_path, endian=endian, target=target, bmc_type=self.bmc_type,
                               fw_info={
                                   "manufacturer": manufacturer.lower(),
                                   "product": product.lower(),
                                   "version": version.lower()
                               },
                               debug=debug, auto_delete=False) as extractor:
                    results = []
                    for root, _, files in os.walk(extractor.out_dir):
                        for name in files:
                            file_path = os.path.realpath(os.path.join(root, name))
                            if os.path.islink(file_path):
                                continue
                            if not os.path.isfile(file_path):
                                continue
                            if file_path in self.scanned_file_path_map[rule_name]:
                                continue
                            self.scanned_file_path_map[rule_name].add(file_path)
                            for sub_rule in rule["detail"]:
                                sub_rule_name = sub_rule['name']
                                path_pattern = sub_rule['path_pattern']
                                file_type = sub_rule['file_type']
                                if self.magic.identify_path(Path(file_path)).output.ct_label not in file_type:
                                    continue
                                if re.search(path_pattern, file_path) is None:
                                    continue
                                with Scanner(bin_path=Path(file_path), rule=rule, debug=self.debug) as scanner:
                                    result = scanner.scan()
                                    if result:
                                        logger.success(f"Hit {rule_name}:{sub_rule_name} at {file_path}")
                                        results.append(result)
                    if results:
                        self.report[rule_name] = results
