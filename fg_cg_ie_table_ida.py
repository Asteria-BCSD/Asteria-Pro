#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: fg_cg_ie_table_ida.py
Description: generate callee relations and import export table
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/8/31
-----------------End-----------------------------
"""

import idaapi
import idautils
import idc
from pathlib import Path
from collections import defaultdict
from tqdm import tqdm
import networkx as nx
from utils.tool_function import write_pickle, write_json


class CallViewer(object):
    """
    generate caller and callee for each function
    """

    def __init__(self):
        self._callee_graph = nx.DiGraph()

    def get_callee_graph(self):
        """
        :return: callee_graph
        """
        if self._callee_graph:
            return self._callee_graph

        bar = tqdm(list(idautils.Functions()))
        for callee_ea in bar:
            # function_ea:
            callee_name = idaapi.get_func_name(callee_ea)
            bar.set_description(f'generate callers for {callee_name}')
            for caller_ea in idautils.CodeRefsTo(callee_ea, 0):
                caller_name = idaapi.get_func_name(caller_ea)
                if caller_name:
                    self._callee_graph.add_node(caller_name, ea=caller_ea)
                    self._callee_graph.add_node(callee_name, ea=callee_ea)
                    if callee_name not in self._callee_graph[caller_name]:
                        self._callee_graph.add_edge(caller_name, callee_name, num=1)
                    else:
                        self._callee_graph[caller_name][callee_name]['num'] += 1

        return self._callee_graph

    def save(self, save_path):
        """
        保存结果到本地
        :param save_path:
        :return:
        """
        write_pickle(self.get_callee_graph(), save_path)


class IEViewer(object):
    """
    generate import and export table list
    """

    def __init__(self):
        self._imports = []
        self._exports = []

    def imports_names_cb(self, ea, name, ord):
        tmp = name.split('@@')
        if len(tmp) == 1:
            self._imports.append([ord, ea, tmp[0], ''])
        else:
            self._imports.append([ord, ea, tmp[0], tmp[1]])
        return True

    def get_imports(self, only_name=False):
        if self._imports:
            return [item[2:] for item in self._imports] if only_name else self._imports

        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            idaapi.enum_import_names(i, self.imports_names_cb)
        self._imports.sort(key=lambda x: x[2])
        return [item[2:] for item in self._imports] if only_name else self._imports

    def get_exports(self, only_name=False):
        if self._exports:
            return [item[3] for item in self._exports] if only_name else self._exports
        self._exports = list(idautils.Entries())
        return [item[3] for item in self._exports] if only_name else self._exports

    def save(self, save_path='imports_exports.json', only_name=False):
        save_data = {
            'imports': self.get_imports(only_name),
            'exports': self.get_exports(only_name),
        }
        write_json(save_data, save_path)


def main():
    call_graph = CallViewer().get_callee_graph()
    ie_viewer = IEViewer()
    if len(idc.ARGV) == 2:
        save_path = idc.ARGV[1]
    else:
        bin_path = Path(idc.get_input_file_path()).resolve()
        save_path = bin_path.parent.joinpath(f'cg_ie_table.pkl')
    import_funcs = ie_viewer.get_imports(only_name=True)
    export_funcs = ie_viewer.get_exports(only_name=True)
    write_pickle({
        'call_graph': call_graph,
        'imports': import_funcs,
        'exports': export_funcs,
    }, save_path)


if __name__ == '__main__':
    idaapi.auto_wait()
    main()
    idc.qexit(0)
