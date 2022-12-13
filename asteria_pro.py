#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""

"""
import numpy as np
from pathlib import Path
from cptools import LogHandler, read_pickle, read_json, write_json
from fg_cg_ie_table import gen_cg_ie_table
from fg_ast import gen_ast
from settings import FILTER_THRESHOLD
from utils.tool_function import tranverse_call_list, get_lcs_simi, get_match_num
from feat_encoding import encode_ast, asteria


class AsteriaPro(object):

    def __init__(self):
        self.logger = LogHandler('Asteria-Pro')
        self._data_cache = {}

    def _transform_callee_list(self, src_func, src_cg_ie_table, tgt_cg_ie_table):
        hash_ = f"{src_func}_{id(src_cg_ie_table)}_{id(tgt_cg_ie_table)}"
        if hash_ in self._data_cache.keys():
            return self._data_cache[hash_]

        src_callee_list = tranverse_call_list(call_graph_node=src_cg_ie_table['call_graph'][src_func],
                                              imports=set([data[0] for data in src_cg_ie_table['imports']]),
                                              exports=set(src_cg_ie_table['exports']))
        cg, imports, exports = tgt_cg_ie_table['call_graph'], set(
            [data[0] for data in tgt_cg_ie_table['imports']]), set(
            tgt_cg_ie_table['exports'])
        self._data_cache[hash_] = (src_callee_list, cg, imports, exports)
        return self._data_cache[hash_]

    def filter(self, src_func, src_cg_ie_table, tgt_cg_ie_table):
        """
        filter out candidate functions with callee similarity
        :param src_func:
        :param src_cg_ie_table:
        :param tgt_cg_ie_table:
        :return:
        """
        src_callee_list, cg, imports, exports = self._transform_callee_list(src_func, src_cg_ie_table, tgt_cg_ie_table)

        cand_funcs = []
        for func in cg.nodes:
            callee_list = tranverse_call_list(cg[func], imports, exports)
            if get_lcs_simi(src_callee_list, callee_list) >= FILTER_THRESHOLD:
                cand_funcs.append(func)
        return cand_funcs

    def rank_by_model_simi(self, src_encode_path, tgt_encode_path):
        src_func2encode_info = read_pickle(src_encode_path)
        tgt_func2encode_info = read_pickle(tgt_encode_path)

        src_func = list(src_func2encode_info.keys())[0]
        src_encoding = src_func2encode_info[src_func]['embedding']

        tgt_funcs = []
        tgt_encodings = []
        for func, encode_info in tgt_func2encode_info.items():
            tgt_funcs.append(func)
            tgt_encodings.append(encode_info['embedding'].reshape(-1))
        tgt_encodings = np.array(tgt_encodings)
        simis = asteria.get_simi_by_embedding(src_encoding, tgt_encodings)
        simi_with_func = sorted([(func, simi) for func, simi in zip(tgt_funcs, simis)], key=lambda x: x[1],
                                reverse=True)[:50]  # select top 50 as result
        return simi_with_func

    def rerank(self, src_func, func_with_simi, src_cg_ie_table, tgt_cg_ie_table):
        """
        Rerank results
        :param src_func:
        :param func_with_simi:
        :param src_cg_ie_table:
        :param tgt_cg_ie_table:
        :return:
        """
        src_callee_list, cg, imports, exports = self._transform_callee_list(src_func, src_cg_ie_table, tgt_cg_ie_table)

        rerank_res = []
        for tgt_func, model_simi in func_with_simi:
            tgt_callee_list = tranverse_call_list(cg[tgt_func], imports, exports)
            match_score = get_match_num(src_callee_list, tgt_callee_list)
            rerank_res.append((tgt_func, 0.9 * match_score + 0.1 * model_simi))
        return sorted(rerank_res, key=lambda x: x[1], reverse=True)

    def run(self, src_func, src_bin_path, tgt_bin_path):
        src_bin_path, tgt_bin_path = Path(src_bin_path), Path(tgt_bin_path)

        self.logger.info(f'Generating callee graph and imports exports table for {src_bin_path}')
        exe_res = gen_cg_ie_table(src_bin_path)
        if exe_res['errcode'] != 0:
            self.logger.error('cg ie table generation failed')
            return exe_res
        src_cg_ie_table = read_pickle(exe_res['feat_path'])

        self.logger.info(f'Generating callee graph and imports exports table for {tgt_bin_path}')
        exe_res = gen_cg_ie_table(tgt_bin_path)
        if exe_res['errcode'] != 0:
            self.logger.error('cg ie table generation failed')
            return exe_res
        tgt_cg_ie_table = read_pickle(exe_res['feat_path'])

        cand_funcs = self.filter(src_func, src_cg_ie_table, tgt_cg_ie_table)
        # save cand_funcs as selected funcs for target binary
        cand_func_path = tgt_bin_path.parent.joinpath(f'cand_funcs-{src_bin_path.name}.json')
        write_json(cand_funcs, cand_func_path)

        self.logger.info(f'Generating AST for {src_bin_path}')
        src_func_path = src_bin_path.parent.joinpath(f'src_func-{src_bin_path.name}.json')
        write_json([src_func], src_func_path)
        exe_res = gen_ast(src_bin_path, select_func_path=src_func_path)
        if exe_res['errcode'] != 0:
            self.logger.error('AST generation failed')
            return exe_res
        src_ast_path = exe_res['feat_path']

        self.logger.info(f'Generating AST for {tgt_bin_path}, cand func num:{len(cand_funcs)}')
        exe_res = gen_ast(tgt_bin_path, select_func_path=cand_func_path)
        if exe_res['errcode'] != 0:
            self.logger.error('AST generation failed')
            return exe_res
        tgt_ast_path = exe_res['feat_path']

        self.logger.info(f'Encoding for {src_bin_path}')
        exe_res = encode_ast(feat_path=src_ast_path)
        if exe_res['errcode'] != 0:
            self.logger.error('AST encoding failed')
            return exe_res
        src_encode_path = exe_res['encode_path']

        self.logger.info(f'Encoding for {tgt_bin_path}')
        exe_res = encode_ast(feat_path=tgt_ast_path)
        if exe_res['errcode'] != 0:
            self.logger.error('AST encoding failed')
            return exe_res
        tgt_encode_path = exe_res['encode_path']

        self.logger.info('Rank result with model similarity')
        res_by_model_simi = self.rank_by_model_simi(src_encode_path, tgt_encode_path)

        self.logger.info('Reranking ....')
        res_by_reranking = self.rerank(src_func,
                                       func_with_simi=res_by_model_simi,
                                       src_cg_ie_table=src_cg_ie_table,
                                       tgt_cg_ie_table=tgt_cg_ie_table)
        return {
            'res_by_filter': cand_funcs,
            'res_by_model': res_by_model_simi,
            'res_by_reranking': res_by_reranking
        }


def main(args):
    ap = AsteriaPro()
    # res = ap.run(src_func='ASN1_verify',
    #              src_bin_path='sample_bins/vul_bin/openssl-1.0.1j',
    #              tgt_bin_path='sample_bins/target_bin/libcrypto.so.1.0.0')
    res = ap.run(src_func=args.vul_func,
                 src_bin_path=args.vul_bin,
                 tgt_bin_path=args.target_bin)
    print('-' * 10 + 'The number of functions after filter' + '-' * 10)
    print(len(res['res_by_filter']))
    print('-' * 10 + 'Results output by asteria model' + '-' * 10)
    print(res['res_by_model'])
    print('-' * 10 + 'Results output by reranking' + '-' * 10)
    print(res['res_by_reranking'])


if __name__ == '__main__':
    import argparse

    ap = argparse.ArgumentParser(description='Asteria-Pro')
    ap.add_argument("-f", "--vul_func", type=str, help="vulnerable function name")
    ap.add_argument("-v", "--vul_bin", type=str, help="binary contains vulnerable function")
    ap.add_argument("-t", "--target_bin", type=str, help="path to target binary")
    args = ap.parse_args()
    main(args)
