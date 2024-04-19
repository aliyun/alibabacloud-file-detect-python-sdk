# -*- coding: utf-8 -*-
from enum import Enum

from .ERR_CODE import ERR_CODE


class DetectResult(object):
    
    class RESULT(Enum):
        RES_WHITE = 0 # 样本白
        RES_BLACK = 1 # 样本黑
        RES_UNKNOWN = 2 # 未知样本
    

    def __init__(self):
        self.md5 = None # 样本md5
        self.time = 0 # 用时，单位为毫秒

        self.error_code = ERR_CODE.ERR_INIT # 错误码
        # 扩展错误信息，如果error_code 为 ERR_CALL_API，此字段有效
        # 此字段为json字符串，格式如下
        # { "action":"xxx", "error_code":"yyy", "error_message":"zzz" }
        # yyy为错误码，如 ServerError
        # zzz为错误信息， 如：ServerError
        # xxx为api的名字 如：CreateFileDetectUploadUrl
        # 当网络出现问题时(未获取到服务应答)，返回 
        # {"action":"xxx", "error_code":"NetworkError", "error_message":"zzz"}
        self.error_string = None # 扩展错误信息
        
        self.result = self.RESULT.RES_UNKNOWN # 检测结果
        self.score = 0 # 分值，取值范围0-100
        self.virus_type = None # 病毒类型，如“黑客工具”
        self.ext_info = None # 扩展信息为json字符串
        self.compresslist = None


    # 检测结果是否完成，True: 可通过getDetectResultInfo查看结果; False: 可通过getErrorInfo获取错误信息
    def isSucc(self):
        return self.error_code == ERR_CODE.ERR_SUCC


    # 获取错误信息
    def getErrorInfo(self):
        if self.isSucc():
            return None
        info = self.ErrorInfo()
        info.md5 = self.md5
        info.time = self.time
        info.error_code = self.error_code
        info.error_string = self.error_string
        return info


    # 获取检测结果信息
    def getDetectResultInfo(self):
        if not self.isSucc():
            return None
        vinfo = None
        if self.result == self.RESULT.RES_BLACK:
            vinfo = self.VirusInfo()
            vinfo.virus_type = self.virus_type
            vinfo.ext_info = self.ext_info
        info = self.DetectResultInfo(vinfo)
        info.md5 = self.md5
        info.time = self.time
        info.result = self.result
        info.score = self.score
        info.compresslist = self.compresslist
        return info

          
    class ErrorInfo(object):
        def __init__(self):
            self.md5 = None # 样本md5
            self.time = 0 # 用时，单位为毫秒
            self.error_code = ERR_CODE.ERR_INIT # 错误码

            # 扩展错误信息，如果error_code 为 ERR_CALL_API，此字段有效
            # 此字段为json字符串，格式如下
            # { "action":"xxx", "error_code":"yyy", "error_message":"zzz" }
            # yyy为错误码，如 ServerError
            # zzz为错误信息， 如：ServerError
            # xxx为api的名字 如：CreateFileDetectUploadUrl
            # 当网络出现问题时(未获取到服务应答)，返回 
            # {"action":"xxx", "error_code":"NetworkError", "error_message":"zzz"}
            self.error_string = None


    class VirusInfo(object):
        def __init__(self):
            self.virus_type = None # 病毒类型，如“黑客工具”
            self.ext_info = None # 扩展信息为json字符串


    class DetectResultInfo(object):
        def __init__(self, vinfo=None):
            self.md5 = None # 样本md5
            self.time = 0 # 用时，单位为毫秒
            self.result = DetectResult.RESULT.RES_UNKNOWN # 检测结果
            self.score = 0 # 分值，取值范围0-100
            compresslist = None # 如果是压缩包，并且开启了压缩包解压参数，则此处会输出压缩包内文件检测结果
            self.__virusinfo = vinfo
        
        # 获取病毒信息,如result为RES_BLACK，可通过此接口获取病毒信息
        def getVirusInfo(self):
            return self.__virusinfo
    

    class CompressFileDetectResultInfo(object):
        def __init__(self, path=None):
            self.path = path # 压缩文件路径
            self.result = DetectResult.RESULT.RES_UNKNOWN # 检测结果
            self.score = 0 # 分值，取值范围0-100
            self.__virusinfo = None
        
        # 获取病毒信息,如result为RES_BLACK，可通过此接口获取病毒信息
        def getVirusInfo(self):
            return self.__virusinfo

        def setVirusInfo(self, vinfo):
            self.__virusinfo = vinfo
        