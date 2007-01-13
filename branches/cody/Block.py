#!/usr/bin/env python

import os, sys, time, struct, string

#from Number import Number
#from String import String

class Block:
    def __init__(self, name):
        self.name = name
        self.open = True

class ContainerBlock(Block):
    def __init__(self, name):
        self.blocks = []
    
        Block.__init__(self, name)
        
    def create_block(self, name):
        bidx = len(self.blocks) - 1
        
        while bidx >= 0:
            block = self.blocks[bidx]
            if block.open:
                return block.create_block(name)

            bidx -= 1

        print "[!] Creating new child in %s" % self.name
        child_block = ContainerBlock(name)
        self.blocks.append(child_block)
        
        return True

    def close_block(self, name):
        for block in self.blocks:
            # Ghetto hack around diff blocks
            try:
                block.close_block(name) 
            except:
                pass
        
        if self.name == name:
            print "[*] Closing %s block" % (block.name)
            self.open = False
            return True
        
        return False
    
    def get_block(self, name):
        bidx = len(self.blocks) - 1
        
        while bidx >= 0:
            block = self.blocks[bidx]
            ro = block.get_block(name)
            if ro:
                return ro
            bidx -= 1
        
        if self.name == name:    
            print "[*] Returning this object %s" % (self.name)
            return self
        else:
            return False

    def add_number(self, name, size, values=[], comment="", pad=True, padval="\x00", endian=">", fuzz="smart"):
        bidx = len(self.blocks) - 1
        
        while bidx >= 0:
            block = self.blocks[bidx]
            if block.open:
                block.add_number(name, size, values, comment, padval, endian, fuzz)
                
                return True
        
            bidx -= 1
            
        print "[*] Open %s adding data" % (self.name)
        
        data_block = DataBlock(name, size, values, comment, padval, endian, fuzz)
        data_block.open = False
        self.blocks.append(data_block)
        
        return True
    
    def add_string(self):
        pass
    
    def add_raw(self, data):
        # Do some shit with the data, parse it
        
        pass
    
    def add_size(self, dtype):
        bidx = len(self.blocks) - 1
        
        while bidx >= 0:
            block = self.blocks[bidx]
            if block.open:
                block.add_size(name, dtype)
                
                return True
        
            bidx -= 1
            
        print "[*] Open %s adding data" % (self.name)
        
        data_block = DynamicBlock(name, dtype)
        data_block.open = False
        self.blocks.append(data_block)
    
    def add_crc(self):
        pass
    
    def add_crc32(self):
        pass
    
    def dump_data(self, data):
        for block in self.blocks:
            block.dump_data(data)
        
        return True
        
class DataBlock(Block):
    def __init__(self, name, size, values=[], comment="", pad=True, padval="\x00", endian=">", fuzz="smart"):

        self.size = size
        self.values = values
        self.comment = comment
        self.pad = pad
        self.padval = padval
        self.endian = endian
        self.fuzz = fuzz
        
        Block.__init__(self, name)
       
    def get_block(self, name):
        if self.name == name:    
            print "[*] Returning this object %s" % (self.name)
            return self
        else:
            return False
    
    def dump_data(self, data):
        for value in self.values:
            size = len("%x" % value) / 2
            if size < self.size and self.pad:
                v = long((padval * self.size - size) + ("%d" % value))
             
            data.append(value)
                
class StaticBlock(Block):
    def __init__(self, name, values=[]):
        self.values = values
        
        Block.__init__(self, name)
    
    def get_block(self, name):
        if self.name == name:    
            print "[*] Returning this object %s" % (self.name)
            return self
        else:
            return False

    def dump_data(self, data):
        for value in self.values:
            data.append(value)
    
class DynamicBlock(Block):
    def __init__(self, name, dtype):
        self.dtype = dtype
        
        Block.__init__(self, name)

    def get_block(self, name):
        if self.name == name:    
            print "[*] Returning this object %s" % (self.name)
            return self
        else:
            return False

    def dump_data(self, data):
        data.append(dtype)