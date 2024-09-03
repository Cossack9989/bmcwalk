import os

from pathlib import Path
from magika import Magika

from mgtool import AnalysisIpmiLib, Extractor


def test_scan_on_sa5212m4_bmc(debug=True):
    m = Magika()
    example_fw_path = os.path.join(os.path.dirname(__file__), "examples", "SA5212M4_BMC_4.35.0_Standard_20191025")
    with Extractor(fw_path=example_fw_path, endian="little", target="root", fw_info={"vendor": "Inspur", "product": "", "version": ""}, debug=debug) as extractor:
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
                    if b"_MsgHndlrTbl\0" in f.read():
                        with AnalysisIpmiLib(ipmi_lib_path=Path(file_path), debug=debug) as analyzer:
                            analyzer.display_cmd_handler_with_cmd_switch()


test_scan_on_sa5212m4_bmc()
