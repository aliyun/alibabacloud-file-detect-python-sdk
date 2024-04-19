# -*- coding: utf-8 -*-

from enum import Enum

class ERR_CODE(Enum):
    ERR_INIT = -100 # 需要初始化，或者重复初始化
    ERR_FILE_NOT_FOUND = -99 # 文件未找到
    ERR_DETECT_QUEUE_FULL = -98 # 检测队列满
    ERR_CALL_API = -97  # 调用API错误
    ERR_TIMEOUT = -96  # 超时
    ERR_UPLOAD = -95  # 文件上传失败；用户可重新发起检测，再次尝试
    ERR_ABORT = -94  # 程序退出，样本未得到检测
    ERR_TIMEOUT_QUEUE = -93  # 队列超时，用户发起检测频率过高或超时时间过短
    ERR_MD5 = -92 # MD5格式不对
    ERR_URL = -91 # URL格式不对
    ERR_SUCC = 0 # 成功
