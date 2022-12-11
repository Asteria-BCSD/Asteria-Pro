#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Utilize BCSD model to encode asteria features
"""
import time
from pathlib import Path
import torch

from tqdm import tqdm

from settings import DEVICE, MODEL_PATH, MODEL_ARGS_PATH
from utils.similarity import AsteriaCalculator
from utils.tool_function import read_pickle, write_pickle, write_json


def load_model(device=DEVICE):
    print(f'load model from {MODEL_PATH}')
    args = read_pickle(MODEL_ARGS_PATH)
    args.resume = MODEL_PATH
    return AsteriaCalculator(config=args, device=device)

asteria = load_model()

def encode_ast(feat_path, encode_path=None):
    """
    Embed asteria features into vectors
    :param feat_path:
    :param encode_path:
    :return:
    """
    func2embed_info = {}
    feat_path = Path(feat_path)
    if encode_path is None:
        encode_path = feat_path.parent.joinpath('Asteria_encodings.pkl')
    else:
        encode_path = Path(encode_path)
    if encode_path.exists():
        return {
            'errcode': 0,
            'encode_path': str(encode_path)
        }
    res = {
        'feat_path': str(feat_path),
        'encode_path': str(encode_path)
    }
    try:
        for func_name, func_info in tqdm(read_pickle(feat_path).items(), desc=f'encoding ast at <{asteria.device}>'):
            ast = func_info['ast']
            start = time.time()
            with torch.no_grad():
                embed = asteria.func_embedding(ast)
            func2embed_info[func_name] = {
                'ea': func_info['ea'],
                'embedding': embed,
                'feat_time_cost': func_info.get('time_cost', None),
                'time_cost': time.time() - start
            }
    except EOFError:
        res.update({
            'errcode': 400,
            'errmsg': 'Asteria feature is empty',
        })
    except FileNotFoundError:
        res.update({
            'errcode': 404,
            'errmsg': 'can not find feature path, please generate it first',
        })
    else:
        res.update({
            'errcode': 0,
        })
        write_pickle(func2embed_info, encode_path)
    return res




def main():
    asteria = load_model()



if __name__ == '__main__':
    main()
