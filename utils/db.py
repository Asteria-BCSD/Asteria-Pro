#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: db.py
Description: 
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/8/19
-----------------End-----------------------------
"""
# from mongoengine import Document, StringField, BinaryField, IntField, ListField, connect

class Tree(object):
    """
    Tree structure
    """

    def __init__(self, ins_expr=None):
        """
        :param ins_expr: xxx_t对象
        """
        # self.ins_expr = ins_expr
        self.id = None
        self.parent = None
        self.num_children = 0
        self.children = []
        self.op = None  #
        self.value = None  #
        self.opname = ""  #
        self._depth = -1
        self._size = -1

    def add_child(self, child):
        if child:
            child.parent = self
            self.num_children += 1
            self.children.append(child)

    def size(self):
        if self._size >= 0:
            return self._size
        count = 1
        for i in range(self.num_children):
            count += self.children[i].size()
        self._size = count
        return self._size

    def depth(self):
        if self._depth >= 0:
            return self._depth
        count = 0
        if self.num_children > 0:
            for i in range(self.num_children):
                child_depth = self.children[i].depth()
                if child_depth > count:
                    count = child_depth
            count += 1
        self._depth = count
        return self._depth

    def __str__(self):
        children_ids = [child.id for child in self.children]
        return "<tree.Tree> id:{}, op:{}, opname:{}, value:{}, parent id:{}, children ids:{}".format(self.id,
                                                                                                     self.op,
                                                                                                     self.opname,
                                                                                                     self.value,
                                                                                                     self.parent.opname if self.parent else '',
                                                                                                     children_ids)


