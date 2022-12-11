#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: similarity.py
Description:
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/10/11 
-----------------End-----------------------------
"""
import pickle as pkl
from abc import abstractmethod

import torch

from utils.model import SimilarityTreeLSTM, get_tree_flat_nodes
from utils.db import Tree


class FuncSimiCalculator(object):
    """
    二进制函数相似度计算基类
    """

    def __init__(self, config, *args, **kwargs):
        """
        初始化,读取配置，加载模型
        :param kwargs:
        """
        self.model = self.load_model(config=config)

    @abstractmethod
    def load_model(self, config, *args, **kwargs):
        """
        加载模型
        """
        raise NotImplementedError

    @abstractmethod
    def func_embedding(self, func):
        """
        对模型进行预先编码，提高后期计算的效率
        :param func: 要编码的函数，属于mongodb Document类型
        :return:
        """
        raise NotImplementedError

    @abstractmethod
    def get_simi_by_embedding(self, embedding1, embedding2):
        """
        计算两个编码向量的相似度
        :param embedding1:
        :param embedding2:
        :return:
        """
        raise NotImplementedError

    @abstractmethod
    def get_simi(self, func1, func2):
        """
        计算两个函数的相似度
        :param func1:
        :param func2:
        :return: simi score
        """
        raise NotImplementedError


class AsteriaCalculator(FuncSimiCalculator):

    def __init__(self, device=torch.device("cuda:0"), **kwargs):
        self.device = device
        super(AsteriaCalculator, self).__init__(**kwargs)

    def load_model(self, config, **kwargs):
        model = SimilarityTreeLSTM(
            config.vocab_size,
            config.input_dim,
            config.mem_dim,
            config.hidden_dim,
            config.num_classes,
            self.device
        )
        checkpoint = torch.load(config.resume, map_location=self.device)
        model.load_state_dict(checkpoint['model'])
        return model

    def func_embedding(self, func_or_ast):
        if isinstance(func_or_ast, Tree):
            tree_vec = get_tree_flat_nodes(func_or_ast)
            res, _ = self.model.embmodel(func_or_ast, tree_vec.to(self.device))
        # elif isinstance(func_or_ast, FuncInfo):
        #     if func_or_ast.asteria_embed is not None:
        #         return pkl.loads(func_or_ast.asteria_embed)
        #     tree = pkl.loads(func_or_ast.dumped_ast)
        #     tree_vec = get_tree_flat_nodes(tree)
        #     res, _ = self.model.embmodel(tree, tree_vec.to(self.device))

        else:
            raise ValueError('input should be AST')
        return res.detach().cpu().numpy()

    def get_simi_by_embedding(self, embedding1, embedding2):
        embedding1 = torch.Tensor(embedding1).to(self.device)
        embedding2 = torch.Tensor(embedding2).to(self.device)
        return self.model.similarity(embedding1, embedding2).detach().cpu().numpy()[:, 1]

    def get_simi(self, func1, func2):
        embedding1 = self.func_embedding(func1)
        embedding2 = self.func_embedding(func2)
        if embedding1 is None or embedding2 is None:
            return 0
        return self.get_simi_by_embedding(embedding1, embedding2)

