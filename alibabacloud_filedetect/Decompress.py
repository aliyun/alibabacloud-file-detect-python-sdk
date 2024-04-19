# -*- coding: utf-8 -*-

class Decompress(object):
    def __init__(self, open=False, maxlayer=5, maxfilecount=1000):
        self.__open = open # 是否识别压缩文件并解压，默认为false
        self.__maxlayer = maxlayer # 最大解压层数，m_open参数为true时生效
        self.__maxfilecount = maxfilecount # 最大解压文件数，m_open参数为true时生效

    def isOpen(self):
        return self.__open

    def getMaxLayer(self):
        return self.__maxlayer
    
    def getMaxFileCount(self):
        return self.__maxfilecount