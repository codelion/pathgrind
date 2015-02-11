pathgrind[ ![Codeship Status for codelion/pathgrind](https://codeship.com/projects/0b086ae0-9472-0132-1417-26aef3146a55/status?branch=master)](https://codeship.com/projects/62554)
=========
[![alt text](https://zenodo.org/badge/3777/codelion/pathgrind.png "doi")](http://dx.doi.org/10.5281/zenodo.9829)

Path based Dynamic Analysis
(Works for 32-bit programs only)

Requirements
------------
- bzip2
- autoconf
- make
- gcc
- python
- gawk
- 32 bit libraries for ubuntu (sudo apt-get install ia32-libs)
- 32 bit c library for building c programs for testing with pathgrind (sudo apt-get install libc6-dev-i386)

On ubuntu you can install the dependencies using apt-get, e.g. `sudo apt-get install autoconf`

Installation
------------
$ ./install.sh

Configuration
-------------
Configuration file: fuzz/settings.cfg

Execution
---------
CLI: $ ./fuzz/fuzz.py

GUI: $ ./fuzz/gui.py

Example
-------
$ ./fuzz/fuzz.py test6
  
New input are created in testcase/input/

Crash files are be saved in testcase/crash/

Publications
------------
[Exploiting Undefined Behaviors for Efficient Symbolic Execution] (http://asankhaya.github.io/pdf/Exploiting_Undefined_Behaviors_for_Efficient_Symbolic_Execution.pdf), ICSE 2014

[An Empirical Study of Path Feasibility Queries] (http://arxiv.org/abs/1302.4798), CoRR 2013

[A Critical Review of Dynamic Taint Analysis and Forward Symbolic Execution] (http://asankhaya.github.io/pdf/ACriticalReviewofDynamicTaintAnalysisandForwardSymbolicExecution.pdf), Technical Report NUS 2012
