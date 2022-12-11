# Asteria-Pro
Asteria-Pro is a binary code similarity detection tool, an upgraded version of [Asteria](https://github.com/Asteria-BCSD/Asteria).
It can perform fast and accurate vulnerability detection task by utilizing an efficient pre-filter and re-ranking mechanism.

<object data="pics/FAsteria_workflow.pdf" type="application/pdf" width="700px" height="700px">
    <embed src="pics/FAsteria_workflow.pdf">
        <p>This browser does not support PDFs. Please download the PDF to view it: <a href="pics/FAsteria_workflow.pdf">Asteria-Pro Work Flow.</a>.</p>
    </embed>
</object>

## Requirements
- IDA Pro 7.5+: `Asteria Pro` now maily support linux, but can be easily applied to windows
  - Extra python packages are required to install to IDA Python: `pip install cptools tqdm networkx cxxfilt`
- conda:  virtual environment build
## Installation
1. create a new python environment with conda
```shell
conda create --name Asteria-pro python=3.8
```
2. Install pytorch with cuda(optional): It enables faster encoding.
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
Our main entrance is `asteria_pro.py`. We give two sample binaries under `sample_bins`, where one is vulnerability binary which is used to generate features, and the other is target binary used to vulnerability function retrieval. 

`asteria_pro.py` will finish following jobs:
1. Extract call graph and imports exports table of two binaries
2. Filter out candidate functions with callee list 
3. Generate ASTs for vulnerability binary(only for vulnerability function) and target binary(only for candidate functions)
4. Encoding ASTs with model used in Asteria
5. Rerank the result output by above step and output the final result.



