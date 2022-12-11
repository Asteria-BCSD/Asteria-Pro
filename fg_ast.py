#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Main entrance for AST generation
"""
from settings import IDA_PATH, IDA64_PATH, IS_LINUX
from utils.tool_function import get_bin_info, execute_cmd


def gen_ast(bin_path, select_func_path=''):
    bin_info_res = get_bin_info(bin_path)
    if bin_info_res['errcode'] != 0:
        return bin_info_res
    mode = bin_info_res['bin_info']['mode']
    feat_path = bin_path.parent.joinpath(f'Asteria_features.pkl')
    if feat_path.exists():
        return {
            'errcode': 0,
            'feat_path': str(feat_path)
        }
    if '32' in mode:
        cmd = f'{IDA_PATH} -Llog/fg_ast_ida.log -c -A -S"./fg_ast_ida.py {feat_path} {select_func_path}" {bin_path}'
    elif '64' in mode:
        cmd = f'{IDA64_PATH} -Llog/fg_ast_ida.log -c -A -S"./fg_ast_ida.py {feat_path} {select_func_path}" {bin_path}'
    else:
        raise ValueError('mode is not supported.')
    if IS_LINUX:
        cmd = f"TVHEADLESS=1 {cmd}"
    exe_res = execute_cmd(cmd, timeout=3600)
    exe_res['feat_path'] = str(feat_path)
    return exe_res


def main():
    exe_res = gen_ast(bin_path='sample_bins/xxx')
    if exe_res['errcode'] == 0:
        print('Call graph successfully generated')


if __name__ == '__main__':
    main()
