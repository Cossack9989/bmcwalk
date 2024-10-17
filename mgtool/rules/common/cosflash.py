import ida

from ida_name import get_ea_name
from ida_funcs import get_func, func_t
from ida_bytes import get_byte, get_word, get_dword, get_bytes, is_loaded

import sys
import copy
import json

from enum import Enum
from typing import List, Dict, Literal, Set
from pathlib import Path
from loguru import logger
from numpy import uint8, uint16, uint32

from mgtool.core.grep import Grep

# if sys.version_info.major == 3 and sys.version_info.minor >= 12:
#     import importlib
#     spec = importlib.util.spec_from_file_location("grep_for_cve_2023_34335", "../../core/grep.py")
#     Grep = importlib.util.module_from_spec(spec).Grep
# else:
#     import imp
#     Grep = imp.load_source("grep_for_cve_2023_34335", "../../core/grep.py").Grep


class PrivilegeRole(Enum):
    NONE = 0x00
    CALLBACK = 0x01
    USER = 0x02
    OPERATOR = 0x03
    ADMIN = 0x04
    OEM = 0x05
    LOCAL = 0x81
    SYS_IFC = 0x82


class ExCmdHndlrMapItem:
    Cmd: uint8
    Privilege: PrivilegeRole
    CmdHndlr: func_t | uint32
    ReqLen: uint8
    FFConfig: uint16
    IfcSupport: uint16


class NetFnCmdsItemStatus(Enum):
    ENABLED = 0x01
    DISABLED = 0xff


class NetFnCmdsItem:
    CmdNum: uint8
    Status: NetFnCmdsItemStatus
    CmdMask: uint8


class GroupExtStatus(Enum):
    GRPEXT_NA = 0x00
    GRPEXT_HPM = 0x00
    GRPEXT_SSI = 0x02
    GRPEXT_DCMI = 0xDC


class NETFNTableItem:
    NetFn: uint8
    GroupExtCode: GroupExtStatus
    NetFunction: List[NetFnCmdsItem]


class MsgHndlrTblItem:
    NetFn: uint8
    CmdHndlrMap: List[ExCmdHndlrMapItem]


class GrepVuln(Grep):

    def __init__(self, bin_path: Path, debug: bool = False):
        super().__init__(bin_path, debug)
        self.cmd_handler: List[MsgHndlrTblItem] = []
        self.cmd_switch: List[NETFNTableItem] = []

    def prepare(self):
        assert ".data" in self.segments.keys()
        assert ".rodata" in self.segments.keys()
        ami_cmd_handler = self.get_cmd_handler(msg_hndlr_tbl_name="m_MsgHndlrTbl")
        oem_cmd_handler = self.get_cmd_handler(msg_hndlr_tbl_name="oem_MsgHndlrTbl")
        self.cmd_handler = ami_cmd_handler + oem_cmd_handler
        ami_cmd_switch = self.get_cmd_switch(net_fn_tbl_name="CoreNetfntbl")
        oem_cmd_switch = self.get_cmd_switch(net_fn_tbl_name="Netfntbl")
        self.cmd_switch = ami_cmd_switch + oem_cmd_switch

    def parse_net_fn_cmds(self, addr) -> List[NetFnCmdsItem]:
        net_fn_cmds = []
        curr_ea = copy.deepcopy(addr)
        while True:
            curr_net_fn_cmd = NetFnCmdsItem()
            curr_net_fn_cmd.CmdNum = get_byte(curr_ea + 0x00)
            try:
                curr_net_fn_cmd_tmp_status = NetFnCmdsItemStatus(get_byte(curr_ea + 0x01))
            except ValueError:
                self.debug_log(f"hit invalid NetFnCmdsItem.Status({get_byte(curr_ea + 0x01)})@{curr_ea:08x}")
                break
            curr_net_fn_cmd.Status = curr_net_fn_cmd_tmp_status
            curr_net_fn_cmd.CmdMask = get_byte(curr_ea + 0x02)
            net_fn_cmds.append(curr_net_fn_cmd)
            curr_ea += 0x03
        return net_fn_cmds

    def get_cmd_switch(self, net_fn_tbl_name: Literal["Netfntbl", "CoreNetfntbl"]) -> List[NETFNTableItem]:
        if net_fn_tbl_name not in self.name_addr_map.keys():
            return []
        cmd_switch = []
        entry_addr = self.name_addr_map[net_fn_tbl_name]
        curr_ea = copy.deepcopy(entry_addr)
        while True:
            curr_net_fn_table_item = NETFNTableItem()
            curr_net_fn_table_item.NetFn = get_byte(curr_ea + 0x00)
            try:
                curr_net_fn_table_item_tmp_group_ext_code = GroupExtStatus(get_byte(curr_ea + 0x01))
            except ValueError:
                self.debug_log(f"hit invalid NETFNTableItem.GroupExtCode({get_byte(curr_ea + 0x01)})@{curr_ea:08x}")
                break
            curr_net_fn_table_item.GroupExtCode = curr_net_fn_table_item_tmp_group_ext_code
            curr_net_fn_table_item_tmp_netfunction = get_dword(curr_ea + 0x04)
            if not is_loaded(curr_net_fn_table_item_tmp_netfunction):
                self.debug_log(f"hit invalid NETFNTableItem.NetFunction({curr_net_fn_table_item_tmp_netfunction:08x})@{curr_ea:08x}")
                break
            curr_net_fn_table_item.NetFunction = self.parse_net_fn_cmds(curr_net_fn_table_item_tmp_netfunction)
            cmd_switch.append(curr_net_fn_table_item)
            curr_ea += 0x08
        return cmd_switch

    def get_cmd_handler(self, msg_hndlr_tbl_name: Literal["m_MsgHndlrTbl", "oem_MsgHndlrTbl"]) -> List[MsgHndlrTblItem]:
        if msg_hndlr_tbl_name not in self.name_addr_map.keys():
            self.debug_log(f"not found {msg_hndlr_tbl_name}")
            return []
        cmd_handler = []
        entry_addr = self.name_addr_map[msg_hndlr_tbl_name]
        curr_ea = copy.deepcopy(entry_addr)
        while True:
            if get_bytes(curr_ea + 0x01, 0x3) != b'\0\0\0':
                break
            curr_msg_handler_tbl = MsgHndlrTblItem()
            curr_msg_handler_tbl.NetFn = get_byte(curr_ea + 0x00)
            curr_msg_handler_tbl_tmp_cmd_hndlr_map_ptr = get_dword(curr_ea + 0x04)
            # if not is_loaded(curr_msg_handler_tbl_tmp_cmd_hndlr_map_ptr):
            #     self.debug_log(f"hit unloaded invalid MsgHndlrTblItem.CmdHndlrMap({curr_msg_handler_tbl_tmp_cmd_hndlr_map_ptr:08x})@{curr_ea:08x}")
            #     break
            if not self.is_data(curr_msg_handler_tbl_tmp_cmd_hndlr_map_ptr):
                self.debug_log(f"hit not-data invalid MsgHndlrTblItem.CmdHndlrMap({curr_msg_handler_tbl_tmp_cmd_hndlr_map_ptr:08x})@{curr_ea:08x}")
                curr_ea += 0x08
                continue
            curr_msg_handler_tbl.CmdHndlrMap = self.parse_cmd_hndlr_map(curr_msg_handler_tbl_tmp_cmd_hndlr_map_ptr)
            cmd_handler.append(curr_msg_handler_tbl)
            curr_ea += 0x8
        return cmd_handler

    def parse_cmd_hndlr_map(self, addr) -> List[ExCmdHndlrMapItem]:
        cmd_hndlr_map = []
        curr_ea = copy.deepcopy(addr)
        while True:
            if get_bytes(curr_ea + 0x0A, size=2) != b'\xAA\xAA':
                break
            curr_cmd_handler = ExCmdHndlrMapItem()
            curr_cmd_handler.Cmd = get_byte(curr_ea)
            try:
                curr_cmd_handler_tmp_privilege = PrivilegeRole(get_byte(curr_ea + 0x01))
            except ValueError:
                self.debug_log(f"hit invalid ExCmdHndlrMapItem.CmdHndlr({get_byte(curr_ea + 0x01): 02x})@{curr_ea:08x}")
                curr_ea += 0x10
                continue
            curr_cmd_handler.Privilege = curr_cmd_handler_tmp_privilege
            curr_cmd_handler_tmp_pointer = get_dword(curr_ea + 0x04)
            if not self.is_executable_or_extern(curr_cmd_handler_tmp_pointer):
                self.debug_log(f"hit invalid ExCmdHndlrMapItem.CmdHndlr({curr_cmd_handler_tmp_pointer:08x})@{curr_ea:08x}")
                curr_ea += 0x10
                continue
            curr_cmd_handler_tmp_cmd_hndlr = get_func(curr_cmd_handler_tmp_pointer)
            if not curr_cmd_handler_tmp_cmd_hndlr:
                curr_cmd_handler.CmdHndlr = curr_cmd_handler_tmp_pointer
                self.debug_log(f"use extern ExCmdHndlrMapItem.CmdHndlr: `{get_ea_name(curr_cmd_handler_tmp_pointer)})`@{curr_cmd_handler_tmp_pointer:08x}")
            else:
                curr_cmd_handler.CmdHndlr = curr_cmd_handler_tmp_cmd_hndlr
                self.debug_log(f"use internal ExCmdHndlrMapItem.CmdHndlr: `{get_ea_name(curr_cmd_handler_tmp_pointer)}`@{curr_cmd_handler.CmdHndlr.start_ea:08x}")
            curr_cmd_handler.ReqLen = get_byte(curr_ea + 0x08)
            curr_cmd_handler.FFConfig = get_word(curr_ea + 0x0A)
            curr_cmd_handler.IfcSupport = get_word(curr_ea + 0x0C)
            cmd_hndlr_map.append(curr_cmd_handler)
            curr_ea += 0x10
        return cmd_hndlr_map

    def search_cmd_handler(self, segment) -> List[Dict]:
        cmd_handlers_map_list = []
        for addr, name in self.addr_name_map.items():
            if not segment["head"] <= addr < segment["tail"]:
                continue
            if not name.endswith("CmdHndlr"):
                continue
            self.debug_log(f"check `{name}`@{addr:08x}")
            tmp_first_ffconfig = get_bytes(addr + 0x0A, size=2)
            tmp_first_cmdhndlr = get_dword(addr + 0x04)
            if tmp_first_ffconfig != b'\xAA\xAA':
                continue
            if not self.is_executable_or_extern(tmp_first_cmdhndlr):
                continue
            self.debug_log(f"found cmd handler map `{name}`@{addr:08x}")
            cmd_handlers_map = {
                "name": name,
                "addr": addr,
                "handlers": self.parse_cmd_hndlr_map(addr)
            }
            cmd_handlers_map_list.append(cmd_handlers_map)
        return cmd_handlers_map_list

    def display_cmd_switch(self):
        for cmd_switch_item in self.cmd_switch:
            print(f"\tNetFn: {int(cmd_switch_item.NetFn):02x}\n"
                  f"\tGroupExtCode: {cmd_switch_item.GroupExtCode.name}")
            for net_fn_cmd in cmd_switch_item.NetFunction:
                print(f"\t\t{int(net_fn_cmd.CmdNum):02x} -> {net_fn_cmd.Status.name}")

    def display_cmd_handler(self):
        for cmd_handler_item in self.cmd_handler:
            print(f"\tNetFn: {int(cmd_handler_item.NetFn):02x}")
            for cmd_handlr_map_item in cmd_handler_item.CmdHndlrMap:
                if isinstance(cmd_handlr_map_item.CmdHndlr, func_t):
                    print(f"\t\t{int(cmd_handlr_map_item.Cmd):02x} -> `{get_ea_name(cmd_handlr_map_item.CmdHndlr.start_ea)}`@{cmd_handlr_map_item.CmdHndlr.start_ea:08x}")
                else:
                    print(f"\t\t{int(cmd_handlr_map_item.Cmd):02x} -> {int(cmd_handlr_map_item.CmdHndlr):08x}")

    def check_cmd_handler_with_cmd_switch(self, display=False):
        netfn_cmd_map = {}
        for cmd_handler_item in self.cmd_handler:
            netfn = f"{int(cmd_handler_item.NetFn):02x}"
            if netfn not in netfn_cmd_map.keys():
                netfn_cmd_map[netfn] = {}
            for cmd_handler_map_item in cmd_handler_item.CmdHndlrMap:
                cmd = f"{int(cmd_handler_map_item.Cmd):02x}"
                if cmd not in netfn_cmd_map[netfn].keys():
                    netfn_cmd_map[netfn][cmd] = {}
                netfn_cmd_map[netfn][cmd]["Enabled"] = "unknown"
                if isinstance(cmd_handler_map_item.CmdHndlr, func_t):
                    cmd_handler_pointer = f"`{get_ea_name(cmd_handler_map_item.CmdHndlr.start_ea)}`"
                else:
                    cmd_handler_pointer = f"@{int(cmd_handler_map_item.CmdHndlr)}:08x"
                netfn_cmd_map[netfn][cmd]["CmdHndlr"] = cmd_handler_pointer
        for cmd_switch_item in self.cmd_switch:
            netfn = f"{cmd_switch_item.NetFn:02x}"
            if netfn not in netfn_cmd_map.keys():
                self.debug_log(f"not found {netfn} in `cmd_handler`")
                continue
            for net_fn_cmd in cmd_switch_item.NetFunction:
                cmd = f"{int(net_fn_cmd.CmdNum):02x}"
                if cmd not in netfn_cmd_map[netfn].keys():
                    self.debug_log(f"not found {cmd} under {netfn}")
                    continue
                netfn_cmd_map[netfn][cmd]["Enabled"] = "false" if net_fn_cmd.Status == NetFnCmdsItemStatus.DISABLED else "true"
        if display:
            print(json.dumps(netfn_cmd_map, indent=4))
        return netfn_cmd_map

    def do(self, actions: Set):
        task_status = dict()
        if "display" in actions:
            self.check_cmd_handler_with_cmd_switch(display=True)
            task_status["display"] = True
        if "cosflash" in actions:
            task_status["cosflash"] = False
            netfn_cmd_map = self.check_cmd_handler_with_cmd_switch(display=False)
            if "32" in netfn_cmd_map.keys():
                if netfn_cmd_map["32"]["22"]["Enabled"] != "false" and netfn_cmd_map["32"]["23"]["Enabled"] != "false" and netfn_cmd_map["32"]["24"]["Enabled"] != "false":
                    logger.success("found cosflash")
                    task_status["cosflash"] = True
        return task_status

    def do_grep(self, debug: bool):
        if debug:
            return self.do({"cosflash", "display"})
        else:
            return self.do({"cosflash"})
