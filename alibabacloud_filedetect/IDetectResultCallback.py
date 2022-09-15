# -*- coding: utf-8 -*-

from abc import ABCMeta, abstractmethod


class IDetectResultCallback(metaclass=ABCMeta):
    """
    返回调用接口
    @param seq       顺序号，由调用时返回（数值 1-2G循环使用）
    @param file_path 待检测文件路径
    @param res       检测结果
    """
    @abstractmethod
    def onScanResult(self, seq, file_path, res):
        pass
