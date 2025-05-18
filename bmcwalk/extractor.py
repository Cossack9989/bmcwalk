import os
import re
import fdt
import copy
import errno
import string
import shutil
import xxhash

from loguru import logger
from binascii import hexlify
from collections import Counter
from subprocess import check_output, CalledProcessError
from typing import List, Dict, Optional, Literal

from .core.utils import find_all, u32, getTmpDir, decrypt, INSPUR_KEY


class Extractor:

    def __init__(self, fw_path, endian, target, bmc_type: Optional[Literal["MegaRAC", "OpenBMC"]] = None, fw_info: Optional[Dict] = None, debug=False):
        self.FwPath = fw_path
        if not os.path.exists(self.FwPath):
            exit(1)
        self.FwData = open(self.FwPath, "rb").read()
        self.FwHash = xxhash.xxh128(self.FwData).hexdigest()
        self.TargetPart = target
        self.OutImg = f"{os.path.join(getTmpDir(), self.FwHash)}.img"
        self.OutDir = f"{os.path.join(getTmpDir(), self.FwHash)}-{self.TargetPart}-out-files/"
        self.Endian = endian
        self.Debug = debug
        self.FsData = b''
        self.IsMatched = False
        self.bmc_type = bmc_type

        self.FwInfoFromOut = False
        if isinstance(fw_info, dict):
            if "manufacturer" in fw_info.keys() and "product" in fw_info.keys() and "version" in fw_info.keys():
                self.FwInfoFromOut = True
                self.Manufacturer, self.Product, self.Version = fw_info["manufacturer"], fw_info["product"], fw_info["version"]
        if not self.FwInfoFromOut:
            parsed_info = os.path.basename(self.FwPath).split('_')
            if len(parsed_info) != 4:
                logger.error("INCORRECT FW_INFO")
                exit(1)
            self.Manufacturer, self.Product, self.Version = parsed_info[0], parsed_info[1], parsed_info[3]

    def debug_log(self, msg):
        if self.Debug:
            logger.debug(msg)

    def __enter__(self):
        # self.debug_log(f"check hpm {hexlify(self.FwData[:8]).decode()}")
        # if self.FwData[:8] == b'PICMGFWU':
        #     self.FwData = self.FwData[0x55:]
        #     self.debug_log(f"check arm jump {hexlify(self.FwData[:4]).decode()}")
        # if self.FwData[1:4] == b'\x00\x00\xea':
        if os.path.exists(self.OutDir):
            return self
        self.debug_log(f"start extraction")
        if self.extract_bmc():
            return self

        raise AssertionError(f"unable to extract {self.TargetPart}")

    def extract_bmc(self):
        if self.bmc_type == "MegaRAC" or self.bmc_type is None:
            self.megarac_extract_ima_way(self.TargetPart)
            if self.IsMatched: return True
            self.megarac_extract_bin_way(self.TargetPart)
            if self.IsMatched: return True
        if self.bmc_type == "OpenBMC" or self.bmc_type is None:
            self.openbmc_extract(self.TargetPart)
            if self.IsMatched: return True
        return False

    def save_to_img(self, data: bytes):
        self.FsData = data
        open(self.OutImg, "wb").write(data)
        logger.info(f"IMAGE of {self.TargetPart} has been saved to {self.OutImg}")

    def part_extract_squashfs(self, fs_start, fs_size):
        logger.info(f"Found SQUASHFS @ {fs_start:#x}")
        self.save_to_img(self.FwData[fs_start: fs_start + fs_size])
        try:
            out = check_output(["unsquashfs", "-d", self.OutDir, self.OutImg], shell=False)
        except CalledProcessError as e:
            out = e.output
        self.debug_log(f"unsquashfs process output: {out.decode('latin-1')}")
        if os.path.exists(self.OutDir):
            self.IsMatched = True
            self.debug_log(f"SQUASHFS {self.OutImg} is extracted to {self.OutDir}")
        else:
            self.IsMatched = False
            logger.error(f"SQUASHFS {self.OutImg} can not be extracted to {self.OutDir}")

    def part_extract_cramfs(self, fs_start, fs_size, inspur_decrypt=False):
        logger.info(f"Found CRAMFS @ {fs_start:#x}")
        if inspur_decrypt:
            self.save_to_img(decrypt(self.FwData[fs_start: fs_start + fs_size], key=INSPUR_KEY))
        else:
            self.save_to_img(self.FwData[fs_start: fs_start + fs_size])
        if os.path.exists(self.OutDir):
            shutil.rmtree(self.OutDir)
        try:
            out = check_output(["cramfsck", "-x", self.OutDir, self.OutImg], shell=False)
        except CalledProcessError as e:
            out = e.output
        self.debug_log(f"cramfsck process output: {out.decode('latin-1')}")
        if os.path.exists(self.OutDir):
            self.IsMatched = True
            self.debug_log(f"CRAMFS {self.OutImg} is extracted to {self.OutDir}")
        else:
            self.IsMatched = False
            logger.error(f"CRAMFS {self.OutImg} can not be extracted to {self.OutDir}")

    def part_extract_jffs(self, fs_start, fs_size):
        logger.info(f"Found JFFS2 @ {fs_start:#x}")
        self.save_to_img(self.FwData[fs_start: fs_start + fs_size])
        if os.path.exists(self.OutDir):
            shutil.rmtree(self.OutDir)
        try:
            out = check_output(["jefferson", self.OutImg, "-d", self.OutDir], shell=False)
        except CalledProcessError as e:
            out = e.output
        self.debug_log(f"jefferson process output: {out.decode('latin-1')}")
        if os.path.exists(self.OutDir):
            self.IsMatched = True
            self.debug_log(f"JFFS2 {self.OutImg} is extracted to {self.OutDir}")
        else:
            self.IsMatched = False
            logger.error(f"JFFS2 {self.OutImg} can not be extracted to {self.OutDir}")

    def openbmc_extract(self, target: str):
        fdt_head_list = find_all(b'\xd0\x0d\xfe\xed', self.FwData)
        possible_region_list = list()
        for fdt_head in fdt_head_list:
            fdt_size = u32(self.FwData[fdt_head + 4: fdt_head + 8], little=False, signed=False)
            if fdt_head + fdt_size > len(self.FwData):
                continue
            partition_offset_table_list = self.get_offset_from_openbmc_dtb(fdt_head, fdt_size)
            for partition_offset_table in partition_offset_table_list:
                if target not in partition_offset_table.keys():
                    continue
                possible_region_list.append(partition_offset_table[target])
        is_little = True if self.Endian == "little" else False
        for fs_start, fs_size in possible_region_list:
            magic_num = self.FwData[fs_start : fs_start + 4]
            if magic_num == b'hsqs':
                fs_size_fine = u32(self.FwData[fs_start + 0x28: fs_start + 0x2c], signed=False, little=is_little)
                if (fs_size_fine & 0xfff) != 0:
                    fs_size_fine += 0x1000 - (fs_size_fine & 0xfff)
                self.part_extract_squashfs(fs_start, fs_size_fine)
            elif magic_num == b'\x45\x3D\xCD\x28':
                fs_size_fine = u32(self.FwData[fs_start + 4: fs_start + 8], signed=False, little=is_little)
                self.part_extract_cramfs(fs_start, fs_size_fine)
            elif magic_num.startswith(b'\x85\x19') or magic_num.startswith(b'\x84\x19'):
                self.part_extract_jffs(fs_start, fs_size)

            if self.IsMatched:
                break

    def get_offset_from_openbmc_dtb(self, fs_start, fs_size) -> List[Dict]:
        part_name_to_common_name = {
            'rofs': 'root',
            'rwfs': 'overlay',
            'u-boot': 'boot',
            'u-boot-env': 'boot-env',
            'kernel': 'kernel'
        }
        regex_pattern_for_module = f"({'|'.join(part_name_to_common_name.keys())})@([xX0-9a-fA-F]+)"
        fdt_content = fdt.parse_dtb(self.FwData[fs_start: fs_start + fs_size])
        partition_dts_list = fdt_content.search(name="partitions", itype=fdt.ItemType.NODE)
        partition_offset_table_list = list()
        for partition_dts in partition_dts_list:
            partition_offset_table = dict()
            for sub_node in partition_dts.nodes:
                match_result = re.match(regex_pattern_for_module, sub_node.name)
                if not match_result:
                    continue
                target_part, offset_raw = match_result.groups()
                if target_part not in part_name_to_common_name.keys():
                    continue
                for prop in sub_node.props:
                    if prop.name == 'reg':
                        partition_offset_table[part_name_to_common_name[target_part]] = prop.data
            partition_offset_table_list.append(copy.deepcopy(partition_offset_table))
        return partition_offset_table_list

    def megarac_extract_bin_way(self, target):
        if b'[img]: ' in self.FwData and b'[end]' in self.FwData:
            l_vars = {
                'partition_desc_start': -1,
                'partition_desc_end': -1,
            }
            module_name_dict = {
                'root': b'rootfs',
                'boot': b'u-boot',
                'web': b'webfs',
            }
            end_pos = self.FwData.index(b'[end]')
            start_pos = self.FwData.index(b'[img]: ')
            if end_pos - start_pos <= 0x100:
                l_vars['partition_desc_start'] = start_pos
            else:
                while start_pos < end_pos and end_pos - start_pos:
                    start_pos = self.FwData.index(b'[img]: ', __start=start_pos + 7, __end=end_pos)
                    if end_pos - start_pos <= 0x100:
                        l_vars['partition_desc_start'] = start_pos
                        break
            assert l_vars['partition_desc_start'] >= 0
            l_vars['partition_desc_end'] = end_pos

            partition_desc_raw = self.FwData[l_vars['partition_desc_start']:l_vars['partition_desc_end']]
            partition_descs = partition_desc_raw.split(b'[img]: ')
            for partition_desc in partition_descs:
                partition_desc_s = partition_desc.decode("latin-1").split(' ')
                if module_name_dict[target] in partition_desc \
                        and len(partition_desc_s) == 4 \
                        and all(c in string.hexdigits for c in partition_desc_s[0]) \
                        and all(c in string.hexdigits for c in partition_desc_s[1]) \
                        and all(c in string.hexdigits for c in partition_desc_s[2]) \
                        and int(partition_desc_s[0], 16) + int(partition_desc_s[1], 16) < len(self.FwData):
                    fs_start = int(partition_desc_s[0], 16)
                    fs_size = int(partition_desc_s[1], 16)
                    magic_num = self.FwData[fs_start: fs_start + 4]
                    if magic_num == b'\x45\x3D\xCD\x28':
                        self.part_extract_cramfs(fs_start, fs_size)
                    elif magic_num.startswith(b'\x85\x19') or magic_num.startswith(b'\x84\x19'):
                        self.part_extract_jffs(fs_start, fs_size)

                if self.IsMatched:
                    break

    def collect_ima_pattern(self):
        if b'$MODULE$' in self.FwData:
            possible_module_pos_list = find_all(b'$MODULE$', self.FwData)
            possible_pattern_list = [self.FwData[pos:pos+0xc] for pos in possible_module_pos_list]
            assert len(possible_pattern_list) > 0
            return Counter(possible_pattern_list).most_common(1)[0][0]

    def megarac_extract_ima_way(self, target):
        pattern = self.collect_ima_pattern()
        if not pattern:
            return
        self.debug_log(f"`$MODULE$` pattern : {hexlify(pattern[8:])}")
        modules_list = find_all(pattern, self.FwData)
        module_name_dict = {
            'root': b'root',
            'boot': b'boot',
            'os': b'osimage',
            'conf': b'conf',
        }
        if target not in module_name_dict:
            logger.error(f"NOT SUPPORT {target}")
        assert modules_list != []
        is_little = True if self.Endian == "little" else False
        for module_idx in range(len(modules_list)):
            module_pos = modules_list[module_idx]
            module_name_start = module_pos + 0x18
            module_name_end = module_name_start + 0x8
            module_name = self.FwData[module_name_start: module_name_end].replace(b'\0', b'')

            if module_name != module_name_dict[target]:
                continue

            possible_offset_list = [0x1000, 0x1020, 0x1040, 0x10000, 0x10020, 0x10040, 0x40000]
            for possible_offset in possible_offset_list:
                fs_start = module_pos + possible_offset
                if fs_start + 0x8 >= len(self.FwData):
                    self.debug_log(f"{fs_start:08x} is an invalid start of {target}")
                    continue
                magic_num = self.FwData[fs_start: fs_start + 4]
                self.debug_log(f"possible {target} magic @ {fs_start:08x}: {hexlify(magic_num).decode()}")
                if magic_num == b'hsqs':
                    fs_size = u32(self.FwData[fs_start + 0x28: fs_start + 0x2c], signed=False, little=is_little)
                    if (fs_size & 0xfff) != 0:
                        fs_size += 0x1000 - (fs_size & 0xfff)
                    self.part_extract_squashfs(fs_start, fs_size)
                    break
                elif magic_num == b'\x45\x3D\xCD\x28':
                    fs_size = u32(self.FwData[fs_start + 4: fs_start + 8], signed=False, little=is_little)
                    self.part_extract_cramfs(fs_start, fs_size)
                    break

                elif magic_num.startswith(b'\x85\x19') or magic_num.startswith(b'\x84\x19'):
                    if module_idx == len(modules_list) - 1:
                        fs_size = len(self.FwData) - fs_start
                    else:
                        fs_size = modules_list[module_idx + 1] - fs_start
                    self.part_extract_jffs(fs_start, fs_size)
                    break

                else:
                    if self.Manufacturer.lower() == "inspur":
                        decrypted_header = decrypt(ciphertext=self.FwData[fs_start: fs_start + 0x10], key=INSPUR_KEY)
                        if decrypted_header[:4] == b'\x45\x3D\xCD\x28':
                            fs_size = u32(decrypted_header[4:8], signed=False, little=is_little)
                            self.part_extract_cramfs(fs_start, fs_size, inspur_decrypt=True)
                            break
            if self.IsMatched:
                break

        return

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.Debug:
            logger.info(f"remove {self.OutImg}")
            try:
                os.remove(self.OutImg)
            except OSError as e:
                if e.errno != errno.ENOENT: # errno.ENOENT = no such file or directory
                    raise
            logger.info(f"remove {self.OutDir}")
            shutil.rmtree(self.OutDir, ignore_errors=True)
