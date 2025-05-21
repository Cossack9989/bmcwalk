#!/usr/bin/python3

import argparse

from pathlib import Path

from bmcwalk import Operator


parser = argparse.ArgumentParser("BMC FwSpy Nano")
parser.add_argument("--path", type=str, required=True)
parser.add_argument("--bmc-type", type=str, default=None)
parser.add_argument("--rules", type=str, choices=['CVE-2025-23016', 'CVE-2023-34335', 'CVE-2023-34342', 'CVE-2018-25103', 'weak-password'], nargs='+', default=['CVE-2023-34335'])
parser.add_argument("--endian", type=str, choices=['little', 'big'], default='little')
parser.add_argument("--manufacturer", type=str, required=True)
parser.add_argument("--product", type=str, required=True)
parser.add_argument("--version", type=str, required=True)
parser.add_argument("--debug", action="store_true")
args = parser.parse_args()

banner = '''
 _______   ___      ___   ______   __   __  ___       __      ___       __   ___  
|   _  "\\ |"  \\    /"  | /" _  "\\ |"  |/  \\|  "|     /""\\    |"  |     |/"| /  ") 
(. |_)  :) \\   \\  //   |(: ( \\___)|'  /    \\:  |    /    \\   ||  |     (: |/   /  
|:     \\/  /\\   \\/.    | \\/ \\     |: /'        |   /' /\\  \\  |:  |     |    __/   
(|  _  \\\\ |: \\.        | //  \\ _   \\//  /\\'    |  //  __'  \\  \\  |___  (// _  \\   
|: |_)  :)|.  \\    /:  |(:   _) \\  /   /  \\\\   | /   /  \\\\  \\( \\_|:  \\ |: | \\  \\  
(_______/ |___|\\__/|___| \\_______)|___/    \\___|(___/    \\___)\\_______)(__|  \\__) 
                                                                                  
'''


if __name__ == "__main__":
    print(banner)
    op = Operator(debug=args.debug)
    op.scan_image_by_fw_path(Path(args.path), set(args.rules), args.manufacturer, args.product, args.version, args.endian, args.debug)
