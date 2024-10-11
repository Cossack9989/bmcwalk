import idc
import idautils
import ida_lines
import ida_hexrays

import os
import json
import r2pipe
import tempfile

from pathlib import Path
from typing import List

from subprocess import check_output, CalledProcessError

from .core.grep import Grep


class RuleFilter:
    functions: List[str]
    callers: List[str]
    callees: List[str]
    strings: List[str]


class GrepRule(Grep):

    def __init__(self, bin_path: Path, rules: dict, debug: bool = False):
        super().__init__(bin_path, debug)
        self.lang = self.get_lang(str(bin_path))
        if self.lang in ["c with blocks", "c"]:
            self.suffix = ".c"
        elif self.lang in ["objc with blocks", "objc"]:
            self.suffix = ".m"
        else:
            self.suffix = ".cpp"
        self.results = dict()
        self.rules = rules

    def prepare(self):
        assert self.lang in ["c with blocks", "c", "c++ with blocks", "c++", "objc with blocks", "objc", "msvc", "jni"]
        for seg_name in self.executable_segments_name_list:
            self.fix_functions(self.segments[seg_name]["head"], self.segments[seg_name]["tail"])

    def get_lang(self, path: str):
        pipe = r2pipe.open(path)
        pipe.cmd("aaa")
        info = pipe.cmdj("ij")
        pipe.quit()
        if not isinstance(info, dict):
            self.debug_log(f"malformed r2.info, return 'c'(default)")
            return "c"
        if "bin" not in info.keys():
            self.debug_log(f"not found r2.info.bin, return 'c'(default)")
            return "c"
        if not isinstance(info["bin"], dict):
            self.debug_log(f"malformed r2.info.bin, return 'c'(default)")
            return "c"
        if "lang" not in info["bin"].keys():
            self.debug_log(f"not found r2.info.bin.lang, return 'c'(default)")
            return "c"
        return info["bin"]["lang"]

    def fix_functions(self, segment_head, segment_tail):
        for func_ea in idautils.Functions(segment_head, segment_tail):
            func_name = self.get_func_name(func_ea)
            if func_name in self.rules["fix_func_types"].keys():
                self.debug_log(f"{func_name} -> {self.rules['fix_func_types'][func_name]}")
                idc.SetType(func_ea, self.rules['fix_func_types'][func_name])

    def scan_function_by_semgrep(self, name: str, code: str, semgrep_rule_name: str):
        with tempfile.NamedTemporaryFile(suffix=self.suffix, prefix=name, mode="w") as fp:
            fp.write(code)
            fp.flush()
            rule_path = os.path.join(os.path.dirname(__file__), "rules", "semgrep", f"{semgrep_rule_name}.yml")
            self.debug_log(f"Applying {os.path.basename(rule_path)} to {name}")
            try:
                content = check_output(["semgrep", "-f", rule_path, fp.name, "-q", "--json"], shell=False)
            except CalledProcessError as e:
                content = e.output
            if content.startswith(b'{'):
                tmp_data: dict = json.loads(content)
                if "results" in tmp_data.keys() and tmp_data["results"]:
                    self.results[semgrep_rule_name] = []
                self.results[semgrep_rule_name].append(tmp_data["results"])

        if os.path.exists(fp.name):
            os.unlink(fp.name)

    def filter_function(self, rule_filter: RuleFilter, func_ea: int, func_name: str):
        if rule_filter.functions:
            if func_name not in rule_filter.functions:
                return False
        else:
            callers = self.get_caller(func_ea)
            if not set(rule_filter.callers).issubset(callers):
                return False
            callees, strings = self.get_callee_and_strings(func_ea)
            if not set(rule_filter.callees).issubset(callees):
                return False
            if not set(rule_filter.strings).issubset(strings):
                return False
            # TODO: filter by signatures(fuzzy hash or CFG feat)
        return True

    def scan_functions(self, segment_head, segment_tail):
        for func_ea in idautils.Functions(segment_head, segment_tail):
            func_name = self.get_func_name(func_ea)
            for rule in self.rules["detail"]:
                rule_name = rule["name"]
                # TODO: When will all of us embrace python3.11+
                rule_filter = RuleFilter()
                rule_filter.functions = rule["filter"]["functions"]
                rule_filter.callers = rule["filter"]["callers"]
                rule_filter.callees = rule["filter"]["callees"]
                rule_filter.strings = rule["filter"]["strings"]
                if not self.filter_function(rule_filter, func_ea, func_name):
                    continue
                try:
                    decompiled_code = ida_hexrays.decompile(func_ea)
                    if decompiled_code is not None:
                        lines = [ida_lines.tag_remove(s.line) for s in decompiled_code.get_pseudocode()]
                        func_code = "\n".join(lines)
                        self.scan_function_by_semgrep(func_name, func_code, rule_name)
                except Exception as e:
                    self.debug_log(e)
                    pass

    def do_grep(self):
        for seg_name in self.executable_segments_name_list:
            if "init" in seg_name or "fini" in seg_name:
                continue
            self.scan_functions(self.segments[seg_name]["head"], self.segments[seg_name]["tail"])
        return self.results

