import os
import string
import shutil
import xxhash

from loguru import logger
from binascii import hexlify
from collections import Counter
from subprocess import check_output, CalledProcessError

from .core.utils import find_all, u32, getTmpDir, decrypt, INSPUR_KEY


class Extractor:

    def __init__(self, fw_path, endian, target, fw_info=None, debug=False):
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
        self.debug_log(f"start extraction")
        if self.extract_megarac_and_openbmc():
            return self

        raise AssertionError(f"unable to extract {self.TargetPart}")

    def extract_megarac_and_openbmc(self):
        self.ima_extract(self.TargetPart)
        if self.IsMatched:
            return True
        self.bin_extract(self.TargetPart)
        if self.IsMatched:
            return True
        return False

    def saveToImg(self, data: bytes):
        self.FsData = data
        open(self.OutImg, "wb").write(data)
        logger.info(f"IMAGE of {self.TargetPart} has been saved to {self.OutImg}")

    def extract_squashfs(self, fs_start, fs_size):
        logger.info(f"Found SQUASHFS @ {fs_start:#x}")
        self.saveToImg(self.FwData[fs_start: fs_start + fs_size])
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

    def extract_cramfs(self, fs_start, fs_size, inspur_decrypt=False):
        logger.info(f"Found CRAMFS @ {fs_start:#x}")
        if inspur_decrypt:
            self.saveToImg(decrypt(self.FwData[fs_start: fs_start + fs_size], key=INSPUR_KEY))
        else:
            self.saveToImg(self.FwData[fs_start: fs_start + fs_size])
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

    def extract_jffs(self, fs_start, fs_size):
        logger.info(f"Found JFFS2 @ {fs_start:#x}")
        self.saveToImg(fs_start, fs_size)
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

    def bin_extract(self, target):
        if b'[img]: ' in self.FwData and b'[end]' in self.FwData:
            lvars = {
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
                lvars['partition_desc_start'] = start_pos
            else:
                while start_pos < end_pos and end_pos - start_pos:
                    start_pos = self.FwData.index(b'[img]: ', __start=start_pos + 7, __end=end_pos)
                    if end_pos - start_pos <= 0x100:
                        lvars['partition_desc_start'] = start_pos
                        break
            assert lvars['partition_desc_start'] >= 0
            lvars['partition_desc_end'] = end_pos

            partition_desc_raw = self.FwData[lvars['partition_desc_start']:lvars['partition_desc_end']]
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
                        self.extract_cramfs(fs_start, fs_size)
                    elif magic_num.startswith(b'\x85\x19') or magic_num.startswith(b'\x84\x19'):
                        self.extract_jffs(fs_start, fs_size)

                if self.IsMatched:
                    break

    def collectImaPattern(self):
        if b'$MODULE$' in self.FwData:
            possible_module_pos_list = find_all(b'$MODULE$', self.FwData)
            possible_pattern_list = [self.FwData[pos:pos+0xc] for pos in possible_module_pos_list]
            assert len(possible_pattern_list) > 0
            return Counter(possible_pattern_list).most_common(1)[0][0]

    def ima_extract(self, target):
        pattern = self.collectImaPattern()
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
                    self.extract_squashfs(fs_start, fs_size)
                    break
                elif magic_num == b'\x45\x3D\xCD\x28':
                    fs_size = u32(self.FwData[fs_start + 4: fs_start + 8], signed=False, little=is_little)
                    self.extract_cramfs(fs_start, fs_size)
                    break

                elif magic_num.startswith(b'\x85\x19') or magic_num.startswith(b'\x84\x19'):
                    if module_idx == len(modules_list) - 1:
                        fs_size = len(self.FwData) - fs_start
                    else:
                        fs_size = modules_list[module_idx + 1] - fs_start
                    self.extract_jffs(fs_start, fs_size)
                    break

                else:
                    if self.Manufacturer.lower() == "inspur":
                        decrypted_header = decrypt(ciphertext=self.FwData[fs_start: fs_start + 0x10], key=INSPUR_KEY)
                        if decrypted_header[:4] == b'\x45\x3D\xCD\x28':
                            fs_size = u32(decrypted_header[4:8], signed=False, little=is_little)
                            self.extract_cramfs(fs_start, fs_size, inspur_decrypt=True)
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
