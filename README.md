# Asteria pro
TODO: Short description

## Requirements
- IDA Pro 7.5+: `Asteria Pro` now maily support linux, but can be easily applied to windows
  - Under python environment for IDA Pro, some packages need to be installed: `pip install cptools tqdm networkx cxxfilt`
- conda: used to create virtual environment
## Installation
1. create a new python environment with conda
```shell
conda create --name Asteria-pro python=3.8
```
2. Install pytorch with cuda(optional): if you want faster encoding speed
```shell
conda install pytorch==1.12.0 torchvision==0.13.0 torchaudio==0.12.0 cudatoolkit=11.3 -c pytorch
```
3. Install other packages 
```shell
pip install -r requirements.txt
```
## Configuration
Before you start, please take a look at `settings.py` and change the `IDA_PATH, IDA64_PATH` with your own ida path. 

After that, change the `device`(default `cuda:0`) to `cpu` if there is no cuda available on your computer.
## How to use
Our main entrance is `asteria_pro.py`, we give two sample binaries under `sample_bins`, one is vulnerability binary which is used to generate features, the other is target binary used to vulnerability function retrieval. 

`asteria_pro.py` will finish following jobs:
1. Extract call graph and imports exports table of two binaries
2. Filter out candidate functions with callee list 
3. Generate ASTs for vulnerability binary(only for vulnerability function) and target binary(only for candidate functions)
4. Encoding ASTs with model used in Asteria
5. Rerank the result output by above step and output the final result.


## Citation


