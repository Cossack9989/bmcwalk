import ida
import idc
import idautils
import ida_name
import ida_xref

from pathlib import Path
from loguru import logger

from mgtool.core.utils import check_printable, dummy_ida_names


class Grep:
    
    def __init__(self, bin_path: Path, debug: bool = False):
        self.bin_path = str(bin_path.absolute())
        self.debug = debug
        
    def debug_log(self, msg):
        if self.debug:
            logger.debug(msg)
            
    def get_all_segments(self):
        _segments = {}
        _executable_segments_name_list = []
        for ea in idautils.Segments():
            segm_name = idc.get_segm_name(ea)
            _segments[segm_name] = {
                "head": idc.get_segm_start(ea),
                "tail": idc.get_segm_end(ea)
            }
            if idc.get_segm_attr(ea, idc.SEGATTR_TYPE) == idc.SEG_CODE:
                _executable_segments_name_list.append(segm_name)
        self.debug_log(''.join([
            f"{seg_name}:\t{_segments[seg_name]['head']:#x}\t{_segments[seg_name]['tail']:#x}\n" 
            for seg_name in _segments.keys()]))
        return _segments, _executable_segments_name_list

    def get_all_names(self):
        _addr_name_map = {}
        _name_addr_map = {}
        [_addr_name_map.update({
            ea: name
        }) for (ea, name) in idautils.Names()]
        [_name_addr_map.update({
            name: ea
        }) for (ea, name) in idautils.Names()]
        self.debug_log(''.join([
            f"{addr:#x} : {_addr_name_map[addr]}\n" 
            for addr in _addr_name_map.keys()]))
        return _addr_name_map, _name_addr_map
        
    def is_executable_or_extern(self, addr) -> bool:
        for seg_name in self.executable_segments_name_list:
            if self.segments[seg_name]["head"] <= addr < self.segments[seg_name]["tail"]:
                return True
        if "extern" in self.segments.keys():
            if self.segments["extern"]["head"] <= addr < self.segments["extern"]["tail"]:
                return True
        return False

    def is_data(self, addr) -> bool:
        if self.segments[".data"]["head"] <= addr < self.segments[".data"]["tail"]:
            return True
        if self.segments[".rodata"]["head"] <= addr < self.segments[".rodata"]["tail"]:
            return True
        return False

    @staticmethod
    def get_func_name(func_ea):
        old_func_name = idc.get_func_name(func_ea)
        new_func_name = ida_name.demangle_name(old_func_name, 0, ida_name.DQT_FULL)
        func_name = new_func_name if isinstance(new_func_name, str) else old_func_name
        return func_name

    def get_caller(self, func_ea):
        callers = set()
        for x in idautils.XrefsTo(func_ea, ida_xref.XREF_ALL):
            caller_func_name = self.get_func_name(x.frm)
            # https://www.hex-rays.com/products/ida/support/idadoc/609.shtml
            if caller_func_name.split("_")[0] in dummy_ida_names:
                continue
            if caller_func_name not in [""]:
                callers.add(caller_func_name)
        return callers

    def get_callee_and_strings(self, func_ea):
        callees = set()
        strings = set()
        func_name = self.get_func_name(func_ea)
        for h in idautils.FuncItems(func_ea):
            for r in idautils.XrefsFrom(h, 0):
                callee_func_name = idc.get_func_name(r.to)
                # https://www.hex-rays.com/products/ida/support/idadoc/609.shtml
                if callee_func_name.split("_")[0] in dummy_ida_names:
                    continue
                if callee_func_name not in ["", func_name]:
                    callees.add(callee_func_name)
                else:
                    const_string = idc.get_strlit_contents(r.to)
                    if check_printable(const_string):
                        strings.add(const_string.decode("latin-1"))

        return callees, strings

    def prepare(self):
        pass

    def __enter__(self):
        ida.open_database(self.bin_path, run_auto_analysis=True)
        idc.auto_wait()
        self.segments, self.executable_segments_name_list = self.get_all_segments()
        self.addr_name_map, self.name_addr_map = self.get_all_names()
        self.prepare()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.debug_log("close database now")
        ida.close_database(save=self.debug)

    def do_grep(self, debug: bool):
        return
