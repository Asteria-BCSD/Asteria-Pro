#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: fg_function_level.py
Description: Generate feature used in Asteria
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/8/16 
-----------------End-----------------------------
"""
import cptools

try:
    import idaapi
    import idc
    import idautils
    import ida_pro
except ModuleNotFoundError:
    pass
import re
import time
from cptools import LogHandler, ERROR, INFO, WARNING
from tqdm import tqdm
from pathlib import Path
ROOT_PATH = Path(__file__).resolve().parent

from utils.tool_function import write_pickle, read_json
from utils.db import Tree

FILTER_USELESS_FUNC = False

# --------------------------------------初始化全局变量↓----------------------------------------

# 日志配置
logger = LogHandler(name="ASTGenerator", log_path=ROOT_PATH.joinpath('log/'), file=True, stream=False, level=cptools.INFO)


def waiting_analysis():
    logger.info("Waiting for ida to finish analysis")
    idaapi.auto_wait()
    logger.info("Analysis finished")


FUNC_BLACK_LIST = {'dsa_builtin_paramgen2', 'dsa_builtin_paramgen', 'blake2b_compress'}
# --------------------------------------初始化全局变量↑----------------------------------------

def quit_ida(status=0):
    ida_pro.qexit(status)


def load_plugin_decompiler():
    """
    加载反编译插件
    :return:
    """
    is_ida64 = idc.get_idb_path().endswith('.i64')
    if is_ida64:
        idaapi.load_plugin("hexx64")
    else:
        idaapi.load_plugin("hexrays")
        idaapi.load_plugin("hexarm")
    if not idaapi.init_hexrays_plugin():
        logger.error("decompiler plugins load failed. File {}".format(idc.get_input_file_path()))
        ida_pro.qexit(400)




# --------------------------------------AST特征生成↓---------------------------------------
class CTreeVisitor(idaapi.ctree_visitor_t):

    def __init__(self, cfunc):
        """
        :param cfunc: c伪代码
        """
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST | idaapi.CV_INSNS)
        self.cfunc = cfunc
        self.statement_num = 0  # 语句的数量
        self.callee_list = []
        self.root = None  # The root of AST
        self.cur_id = 0  # 记录当前树节点的id
        self.generate_success = False  # 是否成功生成AST

    def visit_insn(self, ins) -> int:
        """
        遍历cfunc中所有语句
        :param ins: cfunc.body -> cblock_t
        :return:
        """
        self.root = self.generate_ast_by_ins(ins)
        if self.root:
            logger.info("Generate function AST successfully.")
            self.generate_success = True
            return 1
        logger.error("Generate AST failed.")
        return 0

    def generate_ast_by_ins(self, ins):
        """
        生成指定语句的AST
        :param ins:
        :return:
        """
        self.statement_num += 1
        ast = Tree(ins)
        ast.id = self.cur_id
        self.cur_id += 1
        ast.op = ins.op
        ast.opname = ins.opname
        if ins.op == idaapi.cit_block:
            # 处理block
            for block_ins in ins.cblock:
                ast.add_child(self.generate_ast_by_ins(block_ins))

        elif ins.op == idaapi.cit_expr:
            # 处理表达式语句
            ast.add_child(self._dump_expr(ins.cexpr))

        elif ins.op == idaapi.cit_while:
            # 处理while语句
            cwhile = ins.cwhile

            ast.add_child(self._dump_expr(cwhile.expr))
            if cwhile.body:
                ast.add_child(self.generate_ast_by_ins(cwhile.body))

        elif ins.op == idaapi.cit_do:
            # 处理do语句
            cdo = ins.cdo

            ast.add_child(self.generate_ast_by_ins(cdo.body))
            ast.add_child(self.generate_ast_by_ins(cdo.expr))

        elif ins.op == idaapi.cit_for:
            # 处理for语句
            cfor = ins.cfor

            ast.add_child(self._dump_expr(cfor.init))  # i=0
            ast.add_child(self._dump_expr(cfor.step))  # i<10
            ast.add_child(self._dump_expr(cfor.expr))  # i++
            ast.add_child(self._dump_expr(cfor.body))  # cinsn_t

        elif ins.op == idaapi.cit_if:
            # 处理if语句
            cif = ins.cif
            cexpr = cif.expr  # condition
            ithen = cif.ithen  # cinsn_t
            ielse = cif.ielse  # cinsn_t or None

            ast.add_child(self._dump_expr(cexpr))
            ast.add_child(self.generate_ast_by_ins(ithen))
            if ielse:
                ast.add_child(self.generate_ast_by_ins(ielse))

        elif ins.op == idaapi.cit_switch:
            # 处理switch语句
            cswitch = ins.cswitch
            ast.add_child(self._dump_expr(cswitch.expr))  # switch condition
            for ccase in cswitch.cases:
                AST = Tree()
                AST.opname = 'case'
                AST.op = ccase.op
                value = 0  # default
                size = ccase.size()  # List of case values. if empty, then 'default' case , 此处只取第一个值, 该对象属性值 ： 'acquire', 'append', 'disown', 'next', 'own
                if size > 0:
                    value = ccase.value(0)
                AST.value = value
                for _ins in ccase.cblock:
                    if _ins:
                        AST.add_child(self.generate_ast_by_ins(_ins))
                ast.add_child(AST)

        elif ins.op == idaapi.cit_return:
            # 处理return语句
            creturn = ins.creturn

            ast.add_child(self._dump_expr(creturn.expr))

        elif idaapi.cit_break <= ins.op <= idaapi.cit_asm:
            # 无需处理的语句
            pass

        else:
            logger.warning("Find ins can not be handled. op:{}".format(ins.opname))

        return ast

    def _dump_expr(self, cexpr):
        """
        包括赋值、关系、逻辑表达式，调用，
        :param cexpr: cexpr_t
        :return:
        """
        ast = Tree(cexpr)
        ast.id = self.cur_id
        self.cur_id += 1
        try:
            ast.op = cexpr.op
        except AttributeError:
            return ast
        ast.opname = cexpr.opname
        if idaapi.cot_asg <= cexpr.op <= idaapi.cot_asgumod:
            # 赋值表达式, 存储数据流信息
            sub_ast1 = self._dump_expr(cexpr.x)
            sub_ast2 = self._dump_expr(cexpr.y)

            ast.add_child(sub_ast1)
            ast.add_child(sub_ast2)

        elif cexpr.op == idaapi.cot_tern:
            # x ? y:z，
            sub_ast1 = self._dump_expr(cexpr.x)
            sub_ast2 = self._dump_expr(cexpr.y)
            sub_ast3 = self._dump_expr(cexpr.z)

            ast.add_child(sub_ast1)
            ast.add_child(sub_ast2)
            ast.add_child(sub_ast3)

        elif idaapi.cot_lor <= cexpr.op < idaapi.cot_neg or cexpr.op == idaapi.cot_idx:
            # 逻辑表达式、关系表达式、算术表达式和索引表达式（双操作数），e.g. x || y, x==y, x+y
            ast.add_child(self._dump_expr(cexpr.x))
            ast.add_child(self._dump_expr(cexpr.y))

        elif idaapi.cot_neg <= cexpr.op < idaapi.cot_call:
            # 单操作数表达式， e.g. ~x
            ast.add_child(self._dump_expr(cexpr.x))

        elif cexpr.op == idaapi.cot_call:
            # call 表达式： x(...)，记录函数调用信息，
            for carg in cexpr.a:
                # carg is carg_t
                ast.add_child(self._dump_expr(carg))

        else:
            # 剩下的类型都是单独做为数字或字符串节点特征存储
            if cexpr.op == idaapi.cot_memref or cexpr.op == idaapi.cot_memptr:
                # 引用和指针: x.m, x->m
                ast.op = idaapi.cot_num
                ast.value = cexpr.m  # member offset
                ast.opname = 'num'
            elif cexpr.op == idaapi.cot_num:
                # 立即数: n
                ast.op = idaapi.cot_num
                ast.value = cexpr.n._value
                ast.opname = 'num'
            elif cexpr.op == idaapi.cot_fnum:
                # fnumber_t
                ast.op = idaapi.cot_num
                ast.value = cexpr.fpc.nbytes
                ast.opname = 'num'
            elif cexpr.op == idaapi.cot_str:
                # 字符串： string
                ast.op = cexpr.op
                ast.value = cexpr.string
                ast.opname = cexpr.opname
            elif cexpr.op == idaapi.cot_obj:
                # obj指向字符串，按照字符串处理
                ast.op = idaapi.cot_str
                try:
                    ast.value = idaapi.get_strlit_contents(cexpr.obj_ea, -1, 0).decode()
                except AttributeError:
                    ast.value = ''
                ast.opname = 'str'
            elif cexpr.op == idaapi.cot_var:
                # 变量：var
                ast.op = idaapi.cot_var
                ast.value = cexpr.v.idx
                ast.opname = 'var'
            elif cexpr.op == idaapi.cit_block:
                # 处理block
                for block_ins in cexpr.cblock:
                    ast.add_child(self.generate_ast_by_ins(block_ins))
            else:
                # 其他表达式，暂不处理
                logger.error("Found expression that can not be handled {}, {}".format(cexpr.op, cexpr.opname))
        return ast

    def get_pseudocode(self):
        sv = self.cfunc.get_pseudocode()
        code_lines = []
        for sline in sv:
            code_lines.append(idaapi.tag_remove(sline.line))
        return "\n".join(code_lines)


class ASTGenerator(object):
    """
    开放给外部的AST生成接口
    """

    def __init__(self):
        self.binpath = Path(idc.get_input_file_path()).resolve()  # path to binary
        self.binname = idc.get_root_filename()
        if len(idc.ARGV) >= 2:
            # feat path
            self.feat_path = Path(idc.ARGV[1])
            try:
                select_func_path = Path(idc.ARGV[2])
                logger.critical('loading select funcs')
                self.select_funcs = read_json(select_func_path)
            except (IndexError, FileNotFoundError):
                self.select_funcs = None
            else:
                if not isinstance(self.select_funcs, list):
                    self.select_funcs = None

        else:
            self.feat_path = Path(f'{self.binname}_Asteria_features.pkl')
            self.select_funcs = None
        self.total_func_num = 0
        self.success_func_num = 0
        self.skip_func_num = 0


    @staticmethod
    def is_useless_func(func_name):
        return bool(re.match('^(sub_)|(\.)|(__).*', func_name))

    def generate_by_func(self, func):
        """
        对指定的函数生成AST
        :param func: <ida_funcs.func_t; proxy of <Swig Object of type 'func_t *' at 0x000001EAA350CD50> >
        :return: FuncInfo object
        """
        func_name = idaapi.get_func_name(func.start_ea)
        if FILTER_USELESS_FUNC and self.is_useless_func(func_name):
            return {
                'errcode': 1,
                'errmsg': 'useless func'
            }
        start = time.time()
        try:
            cfunc = idaapi.decompile(func.start_ea)
        except idaapi.DecompilationFailure:
            # logger.error("Can not decompile of func: {}".format(func_name))
            return {
                'errcode': 2,
                'errmsg': "Can not decompile of func: {}".format(func_name)
            }
        visitor = CTreeVisitor(cfunc)
        visitor.apply_to(cfunc.body, None)
        # 获取邻接矩阵、op序列，数值字符串不变量等一系列数据
        time_cost = time.time() - start
        if visitor.generate_success:
            self.success_func_num += 1

        return {
            'errcode': 0,
            'ast': visitor.root,
            'time_cost': time_cost
        }

    def generate(self):
        """
        对单个二进制的所有函数生成AST
        :return:
        """
        self.total_func_num = idaapi.get_func_qty()
        bar = tqdm(range(self.total_func_num))
        func_name2AST = {}
        for i in bar:
            func = idaapi.getn_func(i)
            func_name = idaapi.get_func_name(func.start_ea)
            if func_name in FUNC_BLACK_LIST:
                logger.warning(f'{func_name} is in black list, skip')
                self.skip_func_num += 1
                continue
            if self.select_funcs and func_name not in self.select_funcs:
                logger.warning(f'{func_name} is not in select funcs, skip')
                continue
            bar.set_description("Processing func {}".format(func_name))
            seg_name = idaapi.get_segm_name(idaapi.getseg(func.start_ea))
            if seg_name[1:3] in ["OA", "OM", "te", "_t"]:
                # 其他架构可能代码段不是 .text
                res = self.generate_by_func(func)
                if res['errcode'] == 0:
                    func_name2AST[func_name] = {
                        'ea': func.start_ea,
                        'ast': res['ast'],
                        'time_cost': res['time_cost']
                    }
                    logger.info(f'Generate AST of {func_name} successfully!')
                else:
                    logger.error(f"Generate AST of {func_name} failed, errmsg: {res['errmsg']}")
        # print(func_name2AST)
        write_pickle(func_name2AST, self.feat_path)
        logger.info(
            "Analysis result -> {}/{}/{}(success/skip/total func num)".format(self.success_func_num, self.skip_func_num, self.total_func_num))


# --------------------------------------AST特征生成↑---------------------------------------


if __name__ == "__main__":
    load_plugin_decompiler()
    waiting_analysis()
    ASTGenerator().generate()
    quit_ida()
