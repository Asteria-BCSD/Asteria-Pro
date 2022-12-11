#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: tool_function.py
Description:
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/8/16 
-----------------End-----------------------------
"""
import hashlib
import re
import sys
import json
import math
from typing import Union
from difflib import SequenceMatcher
import pickle as pkl
from pathlib import Path
import subprocess
from tqdm import tqdm
import cxxfilt
import networkx as nx
from collections import OrderedDict, Counter

def read_json(file_path: Union[str, Path], **kwargs) -> OrderedDict:
    """Read json data into python dict
    Args:
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        json content
    """
    file_path = Path(file_path)
    with file_path.open('rt', **kwargs) as handle:
        return json.load(handle, object_hook=OrderedDict)

def write_json(content: dict, file_path: Union[str, Path], **kwargs):
    """Write dict into json file
    Args:
        content: data dict
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        None
    """
    file_path = Path(file_path)
    with file_path.open('wt', **kwargs) as handle:
        json.dump(content, handle, indent=4, sort_keys=True)


def read_pickle(file_path: Union[str, Path], **kwargs) -> object:
    """Read content of pickle file
    Args:
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        content of pickle file
    """
    file_path = Path(file_path)
    with file_path.open('rb', **kwargs) as handle:
        return pkl.load(handle)


def write_pickle(content: object, file_path: Union[str, Path], **kwargs):
    """Write content to pickle file
    Args:
        content: python object
        file_path: file save path
        **kwargs: other parameters used in open()
    Returns:
        None
    """
    file_path = Path(file_path)
    with file_path.open('wb', **kwargs) as handle:
        pkl.dump(content, handle)


def execute_cmd(cmd, timeout=900):
    """
    execute system command
    :param cmd:
    :param f:
    :param timeout:
    :return:
    """
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)

    except subprocess.TimeoutExpired as e:
        return {
            'errcode': 401,
            'errmsg': 'timeout'
        }
    return {
        'errcode': p.returncode,
        'errmsg': p.stdout.decode()
    }


def get_bin_info(bin_path: Union[str, Path]):
    """
    :param bin_path:
    :return:
    """
    # file only works on linux
    cmd = f"file -b {bin_path}"
    execute_res = execute_cmd(cmd)
    if execute_res['errcode'] == 0:
        bin_info = {
            'arch': '',
            'mode': '',
        }
        msg = execute_res['errmsg']
        if 'ARM' in msg:
            bin_info['arch'] = "ARM"
        elif 'PowerPC' in msg:
            bin_info['arch'] = "PPC"
        elif '386' in msg:
            bin_info['arch'] = "386"
        elif 'MIPS' in msg:
            bin_info['arch'] = 'MIPS'
        elif 'x86-64' in msg:
            bin_info['arch'] = "AMD64"
        if '64-bit' in msg:
            bin_info['mode'] = '64'
        elif '32-bit' in msg:
            bin_info['mode'] = '32'

        if bin_info['arch'] and bin_info['mode']:
            return {
                'errcode': 0,
                'bin_info': bin_info
            }
        else:
            return {
                'errcode': 402,
                'errmsg': f"can not get bin_info:{bin_info}"
            }
    return {
        'errcode': 401,
        'errmsg': f"Command execute failed:{execute_res['errmsg']}"
    }




def recover_func_call(call):
    call = call.lstrip('.')
    if call.startswith('j_'):
        return call[2:]

    if re.match('^(__)|(memset)|(memcpy)|(operator).*', call):
        return None

    if '.' in call:
        # pr_out_uint.isra.28
        return call.split('.')[0]

    try:
        call = cxxfilt.demangle(call)
    except cxxfilt.InvalidName:
        pass

    call = re.sub('<.*?>|\(.*?\)', '', call)
    return call


def recover_call_list(call_list, is_sorted=False):
    results = []

    for call in call_list:
        if call is None:
            continue
        tmp = recover_func_call(call)
        if tmp:
            results.append(tmp)
    if is_sorted:
        return results
    else:
        return sorted(results)


def tranverse_call_list(call_graph_node, imports, exports):
    call_list = []
    for key, values in call_graph_node.items():
        call_list.extend([key for i in range(values['num'])])

    return [key for key in recover_call_list(call_list) if key in imports or key in exports]

def get_lcs_simi(seq1, seq2):
    sm = SequenceMatcher(None, seq1, seq2)
    return sm.ratio()



def get_match_num(src_callee, tgt_callee):
    if len(src_callee) == 0:
        return 0
    c1 = Counter(src_callee)
    c2 = Counter(tgt_callee)
    common_keys = set(c1.keys()).intersection(c2.keys())
    match_num = 0
    for key in common_keys:
        match_num += min(c1[key], c2[key])
    return match_num/len(src_callee)

