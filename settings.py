#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""

"""
import sys
import torch
from pathlib import Path

# replace with your IDA path 
IDA64_PATH = Path('/home/cp/Application/idapro-7.5/idat64')
IDA_PATH = Path('/home/cp/Application/idapro-7.5/idat')

if not IDA_PATH.exists() or not IDA64_PATH.exists():
    raise FileNotFoundError('Can not find ida, please check your ida path')

if torch.cuda.is_available():
    DEVICE = torch.device('cuda:0')
else:
    DEVICE = torch.device('cpu')


PLATFORM = sys.platform
if PLATFORM.startswith('linux'):
    IS_LINUX = True
else:
    IS_LINUX = False

FILTER_THRESHOLD = 0.1

MODEL_PATH = Path('saved/models/Asteria/crossarch_train_100000_1659022264.018625.pt')
MODEL_ARGS_PATH = Path('saved/Asteria_args.pkl')
