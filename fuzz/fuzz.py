#!/usr/bin/env python

#   This file is part of Fuzzgrind.
#   Copyright (C) 2009 Gabriel Campana
#
#   This work is licensed under the terms of the GNU GPL, version 3.
#   See the LICENSE file in the top-level directory.


import getopt
import os
import re
import shutil
import subprocess
import sys
import time

from config import *
from valgrind import *
from stp import *
from score import *
from fault_checker import *

import session


def get_input(filename):
    '''
    Load a file, and return it's content
    
    @param filename: name of the file to load
    @type  filename: str
    '''
    
    fp = open(filename)
    buf = fp.read()
    fp.close()
    
    return buf
    
    
class Input:
    def __init__(self, number, filename, bound, bytes=None):
        self.number = number
        self.filename = filename
        self.bound = bound
        if not bytes:
            self.bytes = get_input(filename)
        else:
            fp = open(filename, 'w')
            fp.write(bytes)
            fp.close()
            self.bytes = bytes


def constraint_implies(c1, c2):

    #print 'check ' + c1.pp() + ' => ' +c2.pp()
    if c1.pp() == c2.pp():
        return True
    
    if c1.name == c2.name == 'unop' and c1.op.op == 'Not1':
        c1 = c1.arg
        c2 = c2.arg
        if c1.name == c2.name == 'binop' and (c1.op, c1.size) == (c2.op, c2.size):
            if c1.op.op == 'CmpLE32S':
                c1 = c1.arg1
                c2 = c2.arg1
    
                if c1.name == c2.name == 'binop' and \
                   (c1.op, c1.arg1.pp(), c1.size) == (c2.op, c2.arg1.pp(), c2.size):
                    binop = c1.op.op
                    if binop == 'Sub32' and c1.arg2.name == 'const' and c2.arg2.const == 'const' and \
                      c1.arg2.const.value < c2.arg2.const.value:
                        return True
    return False
#change value based constraint subsumption
"""
    if c1.name == c2.name == 'unop' and c1.op.op == 'Not1':
        c1 = c1.arg
        c2 = c2.arg
        if c1.name == c2.name == 'binop' and (c1.op, c1.size) == (c2.op, c2.size):
            if c1.op.op == 'CmpEQ32':
                c1 = c1.arg1
                c2 = c2.arg1
    
                if c1.name == c2.name == 'binop' and \
                   (c1.op, c1.arg1.pp(), c1.size) == (c2.op, c2.arg1.pp(), c2.size):
                    binop = c1.op.op
                    if binop == 'Sub32' and c1.arg2.name == 'const' and c2.arg2.const == 'const' and \
                      c1.arg2.const.value < c2.arg2.const.value:
                        return True
"""               


def contraint_subsumption(constraints, new_c, stp):
    '''
    Check whether new_c definitely implies or is definitely implied by another
    constraint.
    
    @param constraints: constraint list
    @type  constraints: Iex list
    @param new_c:       new constraint
    @type  new_c:       Iex
    @param stp:
    @type  stp:         STP
    @param taken:
    @type  taken:       boolean
    '''            
    
    if CONSTRAINT_SUBSUMPTION:
        for c in constraints:
            # c => new_c
            if constraint_implies(c['expr'], new_c):
                return constraints
        
        result = []
        for c in constraints:
            # new_c => c                   
            if not constraint_implies(new_c, c['expr']):
                result.append(c)
            else:
                print 'new_c => c'
    else:
        result = constraints
            
    # don't store stp formula, only query number !
    # stp.query can be modified if two queries depend of same variables with
    # different size (eg. LDle:I8(input(0)) AND LDle:I32(input(0)))
    # print new_c.pp()
    try:
        stp_formula = stp.from_expr_(new_c)
    except STPShiftError, error:
        if DEBUG_LAST:
            print '    ! %s. Skipping constraint!' % error,
        return result
    stp.query.append(stp_formula)
    result.append({ 'expr': new_c, 'n': len(stp.query) - 1 })
    
    return result


def compute_path_constraint(input_file):
    '''
    Get the path constraints for a given input
    
    @param input_file: input filename
    @type  input_file: str
    @return str list
    '''
    
    if not DEBUG_LAST:
        output_filename = run_valgrind(PARAM['PROGNAME'],
                                       PARAM['PROGARG'],
                                       input_file,
                                       taint_stdin=PARAM['TAINT_STDIN'],
                                       max_constraint=PARAM['MAX_BOUND'])
    else:
        output_filename = DEBUG_LAST

    pc = []
    fp = open(output_filename, 'r')
    for line in fp:
        m = re.match('\[\+\] 0x[0-9]+.* depending on input: if \((.*)\) => (\d)', line)
        if m:
            constraint = m.group(1)
            taken = bool(int(m.group(2)))
            pc.append((constraint, taken))
            #print '    + constraint\t%s' % (constraint[:100])    
        elif line == "If that doesn't help, please report this bug to: www.valgrind.org\n" or \
          ('oops, we depend of x86g_calculate_condition' in line and False):
            print '[-] Oops, a bug occured in Valgrind. See /tmp/valgrind_output.txt'
            sys.exit(-1)
        if len(pc) == PARAM['MAX_BOUND']:
            break
    fp.close()
   
    return pc


def expand_execution(input, callbacks):
    '''
    Symbolically execute the program under test with that input, and generate
    new input computed from the expanded path constraints
    
    @param input: input to expand
    @type  input: Input instance
    @return new inputs
    '''
    
    global ninput
    global paths
    global elapsed
    global querytime
    global pathssub
    global totalcon
    global cva_constraints
    global cva_paths
    
    callback_start_constraint_solver = callbacks[0]
    callback_constraint_solved = callbacks[1]
    callback_start_constraint_analyser = callbacks[2]
    callback_constraint_analysed = callbacks[3]
    callback_start_expander = callbacks[4]
    callback_expanded = callbacks[5]
    
    stp = STP()
    threshold = 0
    constraints = []
    child_inputs = []
    

    # compute path constraint
    if not callback_start_expander:
        print '[+] expanding execution with file %s ' % input.filename.split('/')[-1]
    else:
        callback_start_expander(input)

    
    if input.bound in cva_paths:
	print 'CVA: Paths Pruned'
        pc = cva_paths[input.bound]
	#return child_inputs	
    else:
        start = time.time()
	pc = compute_path_constraint(input.filename)
    	querytime = querytime + (time.time() - start)

    if callback_expanded:
        callback_expanded()
    #print '[+] here'
    #parse valgrind's output and do constraint subsumption
    if not callback_start_constraint_analyser:
        print '    * %d path constraints (bound: %d)' % (len(pc), input.bound)
        os.write(sys.stdout.fileno(), '       ')
    else:
        callback_start_constraint_analyser(len(pc))
    j = 1
    for (c, taken) in pc:
        #print c,'   ',taken 
        if not taken:
            c = 'Not1(%s)' % c
        expr = parse_expr(c)
        constraints = contraint_subsumption(constraints, expr, stp) # is input.bound still consistent ?
        stp.first_cmp = True # XXX - dirty
        if not callback_constraint_analysed:
            os.write(sys.stdout.fileno(), '%s%d' % ('\b' * len(str(j - 1)), j))
        else:
            callback_constraint_analysed()
        j += 1
    if not callback_constraint_analysed:
        os.write(sys.stdout.fileno(), '%s' % '\b' * (len(str(j - 1)) + 6))

    totalcon += len(pc)
     
    if len(constraints) != len(pc):
        print '    * %d path constraints (thanks to constraint subsumption)' % len(constraints)
        pathssub += len(constraints)
    
    # all queries are computed, there will not be change anymore, so we can
    # safely create the constraints
    for c in constraints:
        c['stp'] = stp.query[c.pop('n')]
    stp.query = []
    
    if input.bound > len(constraints):
        return child_inputs
    elif input.bound > 0:
        # XXX - we should reuse previous stp.query
        stp.query = [ constraints[j]['stp'] for j in range(0, input.bound) ]
        stp.negate(len(stp.query) - 1)
    
    if callback_start_constraint_solver:
        callback_start_constraint_solver(len(constraints) - input.bound)

    #CVA for infeasible paths    
    
    #infeasible_constraints = []
    
    # solve constraints
    for j in range(input.bound, len(constraints)):
        if not callback_constraint_solved:
            print '    * solving constraints [0:%d]' % j

        value = constraints[j]['stp'].pp()
        #print value
        if value in cva_constraints:
		#print cva_constraints[value]
	        print 'CVA: Constraints Pruned'
		solution = cva_constraints[ value ]
		#if callback_constraint_solved:
	        #        callback_constraint_solved(None)
                #continue
		
        else:
		if stp.query:
		    stp.negate(len(stp.query) - 1)
		
		    if DEBUG_LAST:
		        print '     ', constraints[j-1]['expr'].pp()
		        print '     ', constraints[j-1]['stp'].pp()
		    if DEBUG_LAST or VERIF_SOLVABLE:
		        stp.execute()
		        if not stp.interpret():
		            stp.query.pop()
		            print '    ! unsolvable constraint, skipping it !'
		            sys.exit(0)
		            if callback_constraint_solved:
		                callback_constraint_solved(None)
		            break
		
		#print '***', constraints[j]['stp'].pp()
		
		stp.query += [ constraints[j]['stp'] ]
		stp.negate(len(stp.query) - 1)
		#start = time.time()
		stp.execute()
		#querytime = querytime + (time.time() - start)
	       	solution = stp.interpret()
	       	#print '%s' % solution
       	paths += 1

        if PARAM['PATH_BOUND'] > 0 and paths >= PARAM['PATH_BOUND']:
		return child_inputs

	if CONSTRAINT_SUBSUMPTION:
        	cva_constraints[value] = solution

        if solution:
	    if CONSTRAINT_SUBSUMPTION:
           	 cva_paths[input.bound] = pc
            bytes = list(input.bytes)

            for (byte, (value, size)) in solution.iteritems():
                for i in range(0, size / 8):
                    bytes[byte + i] = chr((value >> (i * 8)) & 0xff)
            bytes = ''.join(bytes)
            
            ninput += 1
            filename = '%s%d%s' % (PARAM['OUTPUT_FOLDER'], ninput, PARAM['EXTENSION'])
            #pathqueryfile = '%s%d%s' % (PARAM['OUTPUT_FOLDER'], ninput,'.stp')
            #f = open(pathqueryfile, 'w')
            #f.write(stp.pp())
            #f.close()
            new_input = Input(ninput, filename, j + 1, bytes)
            child_inputs.append(new_input)


            if not callback_constraint_solved:
                printable_bytes = re.sub('[^\w;\.!\*&~"#\'\{\}\(\)\[\]]', '.', bytes[:10])
                #print '    * new_input (%d%s): %s time_taken : %s' % (ninput, PARAM['EXTENSION'], printable_bytes, elapsed)
		print '    * new_input (%d%s): %s' % (ninput, PARAM['EXTENSION'], printable_bytes)
                #fname = 'time_results_%s' % PARAM['INPUT_FILE'].split('/')[-1]
                #f = open(fname, 'a')
                #f.write('%s,%s\n' % (printable_bytes,elapsed))
	        #f.close()
            else:
                callback_constraint_solved(new_input)
        else:
            # add infesible constraint
            #print '%s' % solution 
            if callback_constraint_solved:
                callback_constraint_solved(None)

    if DEBUG_LAST:
        sys.exit(0)
    
    return child_inputs


def search(target, worklist, callbacks):    
    global ninput
    global paths
    global elapsed
    global querytime
    global start
    global pathssub
    global totalcon
    global cva_constraints
    global cva_paths

    callback_start_scoring = callbacks[6]
    callback_scored = callbacks[7]
    
    callback_start_check = callbacks[8]
    callback_checked = callbacks[9]

    accumlist = list(worklist)
    current = ninput
    #session.save(target, PARAM, ninput, worklist)  
    
    #start = time.time()

    while worklist:
        #start = time.time()
        input = worklist.pop()
        #print '[+] input %s' % input.filename

        child_inputs = expand_execution(input, callbacks)

        if USE_ACCUM:
		continue         
 
	if PARAM['PATH_BOUND'] > 0 and paths >= PARAM['PATH_BOUND']:
           if not USE_ACCUM:
		accumlist += child_inputs
           break;

        if not callback_start_check:
            print '[+] checking each new input'
        else:
            callback_start_check(len(child_inputs))

        for input in child_inputs:
            if not callback_checked:
                os.write(sys.stdout.fileno(), '    %s' % input.filename.split('/')[-1])
            fault = check(PARAM['PROGNAME'], PARAM['PROGARG'], input.filename, PARAM['FAULT_CHECKER'], PARAM['TAINT_STDIN'])
            if not callback_checked:
                os.write(sys.stdout.fileno(), '\b' * (len(input.filename.split('/')[-1]) + 4))
                if fault:
                    print '[+] ' + ('@' * 75)
                    print '    Fault detected on file %s' % input.filename.split('/')[-1]
                    print '    ' + ('@' * 75)
            else:
                callback_checked(input.number, fault)
            if fault:
                filecopy = os.path.join(PARAM['CRASH_FOLDER'], os.path.basename(input.filename))
                shutil.copy(input.filename, filecopy)

        #elapsed = elapsed + (time.time() - start)

	if not callback_start_scoring:
	    print '[+] scoring each new input'
	else:
	    callback_start_scoring(len(child_inputs))

	for input in child_inputs:
	    if not callback_scored:
	        os.write(sys.stdout.fileno(), '    %s' % input.filename.split('/')[-1])
	    input.note = score(PARAM['PROGNAME'], PARAM['PROGARG'], input.filename, PARAM['TAINT_STDIN'])
	    #input.note = random_score()
	    if not callback_scored:
	        os.write(sys.stdout.fileno(), '\b' * (len(input.filename.split('/')[-1]) + 4))
	    else:
	        callback_scored(input)
	    
	worklist += child_inputs
	accumlist += child_inputs
	worklist.sort(key=lambda x: x.note)
	#worklist.sort(key=lambda x: x.note, reverse = True)
        #worklist.reverse()
	# this is counter-intuitive, but a lot of blocks are executed on
	# completely wrong images
	if PARAM['PROGNAME'] == '/usr/bin/convert':
	    worklist.reverse()
        
        #session.save(target, PARAM, ninput, worklist)
 
    elapsed = (time.time() - start)
    session.save(target, PARAM, ninput, accumlist)
    print 'Paths Explored: %s Feasible Paths: %s Total Constraints: %s Actual Constraints: %s Time Taken: %s Valgrind Time: %s'\
          % (paths,ninput - current,totalcon,pathssub,round(elapsed,2),round(querytime,2))

def usage():
    print 'Usage: %s <parameter name>' % sys.argv[0]
    print '  -h --help\t\t\tshow summary of options'
    print '  -c --config\t\t\tconfiguration file'
    print '  -o --subsumption\t\tactivate constraint subsumption'
    print '  -s --session\t\t\tload saved session if present'
    print '  -l --last [vg_output_i.txt]\tdebug on last valgrind output'
    print '  -v --verif\t\t\tverify that constraints are coherent'
    sys.exit(0)
            
            
if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hcsl:ov', ['help', 'config', 'session', 'last', 'subsumption', 'verif'])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(-1)
        
    if len(args) != 1:
        usage()
        sys.exit(-1)
    
    configfile = 'fuzz/settings.cfg'
    worklist               = None
    DEBUG_LAST             = False
    VERIF_SOLVABLE         = False
    CONSTRAINT_SUBSUMPTION = False
    USE_ACCUM = False
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
            sys.exit(0)
        elif o in ('-c', '--config'):
            configfile = args[0]
        elif o in ('-s', '--session'):
	    PARAM = get_config(configfile, args[0])
            (name,ext) = PARAM['PROGNAME'].split('.') 
	    PARAM['PROGNAME'] = name +'_cva' + ext
            PARAM, ninput, worklist = session.load(args[0])
            USE_ACCUM = True
            if not worklist:
                print 'Fuzzing done'
                sys.exit(0)
        elif o in ('-l', '--last'):
            DEBUG_LAST = a
        elif o in ('-o', '--subsumption'):
            CONSTRAINT_SUBSUMPTION = True
        elif o in ('-v', '--verif'):
            VERIF_SOLVABLE = True
        else:
            assert False, 'unhandled option'
            
    target = args[0]
    elapsed = 0
    querytime = 0
    paths = 0
    pathssub = 0 
    start = time.time()
    totalcon = 0
    cva_constraints = {}
    cva_paths = {}
    if not worklist:
        PARAM = get_config(configfile, target)
        ninput = PARAM.get('N', 0)
        input_seed = Input(0, PARAM['INPUT_FILE'], PARAM.get('MIN_BOUND', 0))
        worklist = [ input_seed ]
    
    search(target, worklist, [ None ] * 10)
