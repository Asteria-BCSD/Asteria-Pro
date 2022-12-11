#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Main entrance for call graph generation
"""
from settings import IDA_PATH, IDA64_PATH, IS_LINUX
from utils.tool_function import get_bin_info, execute_cmd


def gen_cg_ie_table(bin_path):
    bin_info_res = get_bin_info(bin_path)
    if bin_info_res['errcode'] != 0:
        return bin_info_res
    mode = bin_info_res['bin_info']['mode']
    feat_path = bin_path.parent.joinpath(f'cg_ie_table.pkl')
    if feat_path.exists():
        return {
            'errcode': 0,
            'feat_path': str(feat_path)
        }
    if '32' in mode:
        cmd = f'{IDA_PATH} -Llog/fg_cg_ie_table_ida.log -c -A -S"./fg_cg_ie_table_ida.py {feat_path}" {bin_path}'
    elif '64' in mode:
        cmd = f'{IDA64_PATH} -Llog/fg_cg_ie_table_ida.log -c -A -S"./fg_cg_ie_table_ida.py {feat_path}" {bin_path}'
    else:
        raise ValueError('mode is not supported.')
    if IS_LINUX:
        cmd = f"TVHEADLESS=1 {cmd}"

    exe_res = execute_cmd(cmd, timeout=1200)
    exe_res['feat_path'] = str(feat_path)
    return exe_res


def main():

    exe_res = gen_cg_ie_table(bin_path='/xxx')
    if exe_res['errcode'] == 0:
        print('Call graph successfully generated')


if __name__ == '__main__':
    main()
