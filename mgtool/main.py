import os
import sys
import yaml

from typing import Set
from types import NoneType
from pathlib import Path
from loguru import logger


if sys.version_info.major == 3 and sys.version_info.minor >= 12:
    import importlib
else:
    import imp


from .grep_rule import GrepRule


self_dirt = os.path.dirname(__file__)
rule_dirt = os.path.join(self_dirt, "rules")
assert os.path.exists(rule_dirt)


class Scanner:

    def __init__(self, bin_path: Path, rule_name_set: Set[str], debug: bool = False):
        self.rule_set = []
        self.bin_path = bin_path
        self.debug = debug
        for rule_name in rule_name_set:
            rule_path = os.path.join(rule_dirt, f"{rule_name}.yml")
            with open(rule_path) as rule_stream:
                self.rule_set.append(yaml.safe_load(rule_stream))

    def prepare(self):
        for rule in self.rule_set:
            assert "idat" in rule.keys() and os.path.exists(rule["idat"]), "rule.idat should be set to the real path of idat"
            assert "name" in rule.keys() and isinstance(rule["name"], str), "rule.name should not be (nil)"
            assert "engine" in rule.keys() and rule["engine"] in ["semgrep", "common"], "rule.engine should be in semgrep or common"
            assert "detail" in rule.keys() and isinstance(rule["detail"], list), "rule.detail should be a list"
            assert "fix_func_types" in rule.keys() and isinstance(rule["fix_func_types"], (dict, NoneType)), "rule.fix_func_types should be dict | null"
            if rule["engine"] == "common":
                for rule_detail in rule["detail"]:
                    assert isinstance(rule_detail, dict)
                    assert "name" in rule_detail.keys()
                    rule_script = os.path.join(rule_dirt, "common", f"{rule_detail['name']}.py")
                    assert os.path.exists(rule_script)
                    if sys.version_info.major == 3 and sys.version_info.minor >= 12:
                        spec = importlib.util.spec_from_file_location("GrepVuln", rule_script)
                        user_module = importlib.util.module_from_spec(spec)
                    else:
                        user_module = imp.load_source("GrepVuln", rule_script)
                    rule_detail["grep"] = user_module
            elif rule["engine"] == "semgrep":
                for rule_detail in rule["detail"]:
                    assert isinstance(rule_detail, dict)
                    assert "name" in rule_detail.keys()
                    rule_config = os.path.join(rule_dirt, "semgrep", f"{rule_detail['name']}.yml")
                    assert os.path.exists(rule_config)

    def __enter__(self):
        self.prepare()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def scan(self, rule: dict):
        if rule["engine"] == "common":
            task_status = dict()
            for rule_detail in rule["detail"]:
                with rule_detail["grep"](self.bin_path, debug=self.debug) as g:
                    task_status[rule_detail["name"]] = g.do_grep(debug=self.debug)
            return task_status
        elif rule["engine"] == "semgrep":
            with GrepRule(self.bin_path, rule, debug=self.debug) as g:
                return g.do_grep()
        else:
            logger.error(f"Engine `{rule['engine']}' is not supported")
            return

    def batch_scan(self):
        results = dict()
        for rule in self.rule_set:
            tmp_result = self.scan(rule)
            if not tmp_result:
                continue
            results[rule["name"]] = tmp_result
        return results
