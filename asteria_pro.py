#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""

"""
from pathlib import Path
from cptools import LogHandler, read_pickle, read_json, write_json, write_pickle

from fg_cg_ie_table import gen_cg_ie_table
from fg_ast import gen_ast
from feat_encoding import encode_ast, asteria
from settings import FILTER_THRESHOLD
from utils.tool_function import tranverse_call_list, get_lcs_simi, get_match_num


class AsteriaPro(object):

    def __init__(self):
        self.logger = LogHandler('Asteria-Pro')

    @staticmethod
    def filter(src_func, src_cg_ie_table, tgt_cg_ie_table):
        """
        filter out candidate functions with callee similarity
        :param src_func:
        :param src_cg_ie_table:
        :param tgt_cg_ie_table:
        :return:
        """
        src_callee_list = tranverse_call_list(call_graph_node=src_cg_ie_table['call_graph'][src_func],
                                              imports=set([data[0] for data in src_cg_ie_table['imports']]),
                                              exports=set(src_cg_ie_table['exports']))
        cg, imports, exports = tgt_cg_ie_table['call_graph'], set(
            [data[0] for data in tgt_cg_ie_table['imports']]), set(
            tgt_cg_ie_table['exports'])

        cand_funcs = []
        for func in cg.nodes:
            callee_list = tranverse_call_list(cg[func], imports, exports)
            if get_lcs_simi(src_callee_list, callee_list) >= FILTER_THRESHOLD:
                cand_funcs.append(func)
        return cand_funcs

    @staticmethod
    def rank_by_model_simi(src_encode_path, tgt_encode_path):
        src_func2encode_info = read_pickle(src_encode_path)
        tgt_func2encode_info = read_pickle(tgt_encode_path)

        for func, encod_info in src_func2encode_info.items():
            src_func = func
            src_encoding = encod_info['embedding']
            break

        tgt_funcs = []
        tgt_encodings = []
        for func, encode_info in tgt_func2encode_info.items():
            tgt_funcs.append(func)
            tgt_encodings.append(encode_info['embedding'].reshape(-1))

        simis = asteria.get_simi_by_embedding(src_encoding, tgt_encodings)
        simi_with_func = sorted([(func, simi) for func, simi in zip(tgt_funcs, simis)], key=lambda x: x[1],
                                reverse=True)[:50]
        return simi_with_func

    @staticmethod
    def rerank(src_func, func_with_simi, src_cg_ie_table, tgt_cg_ie_table):
        src_callee_list = tranverse_call_list(call_graph_node=src_cg_ie_table['call_graph'][src_func],
                                              imports=set([data[0] for data in src_cg_ie_table['imports']]),
                                              exports=set(src_cg_ie_table['exports']))

        cg, imports, exports = tgt_cg_ie_table['call_graph'], set(
            [data[0] for data in tgt_cg_ie_table['imports']]), set(
            tgt_cg_ie_table['exports'])

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
            'res_by_filter': read_json(cand_func_path),
            'res_by_model': res_by_model_simi,
            'res_by_reranking': res_by_reranking
        }


def main():
    ap = AsteriaPro()
    res = ap.run(src_func='ASN1_verify',
                 src_bin_path='sample_bins/vul_bin/openssl-1.0.1j',
                 tgt_bin_path='sample_bins/target_bin/libcrypto.so.1.0.0')
    print('-'*10 + 'after filter'+ '-'*10)
    print(len(res['res_by_filter']))
    print('-'*10 + 'res by asteria model'+ '-'*10)
    print(res['res_by_model'])
    print('-' * 10 + 'res by reranking' + '-' * 10)
    print(res['res_by_reranking'])

if __name__ == '__main__':
    main()
