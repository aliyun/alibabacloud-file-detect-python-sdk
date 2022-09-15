# -*- coding: utf-8 -*-
import os
import sys
from typing import List
import threading
import time
import traceback

from alibabacloud_filedetect.OpenAPIDetector import OpenAPIDetector
from alibabacloud_filedetect.IDetectResultCallback import IDetectResultCallback
from alibabacloud_filedetect.ERR_CODE import ERR_CODE
from alibabacloud_filedetect.DetectResult import DetectResult


class Sample(object):
    
    def __init__(self):
        pass


    """
    同步检测文件接口
    @param detector 检测器对象
    @param path 待检测的文件路径
    @param timeout_ms 设置超时时间，单位为毫秒
    @param wait_if_queuefull 如果检测队列满了，False表示不等待直接返回错误，True表示一直等待直到队列不满时
    """
    def detectFileSync(self, detector, path, timeout_ms, wait_if_queuefull):
        if detector is None or path is None:
            return None
        result = None
        while True:
            result = detector.detectSync(path, timeout_ms)
            if result is None:
                break
            if result.error_code != ERR_CODE.ERR_DETECT_QUEUE_FULL:
                break
            if wait_if_queuefull is False:
                break
            detector.waitQueueAvailable(-1)
        
        return result
    

    """
    异步检测文件接口
    @param detector 检测器对象
    @param path 待检测的文件路径
    @param timeout_ms 设置超时时间，单位为毫秒
    @param wait_if_queuefull 如果检测队列满了，False表示不等待直接返回错误，True表示一直等待直到队列不满时
    @param callback 结果回调函数
    """
    def detectFile(self, detector, path, timeout_ms, wait_if_queuefull, callback):
        if detector is None or path is None or callback is None:
            return ERR_CODE.ERR_INIT.value
        result = ERR_CODE.ERR_INIT.value
        if wait_if_queuefull:
            real_callback = callback
            class AsyncTaskCallback(IDetectResultCallback):
                def onScanResult(self, seq, file_path, callback_res):
                    if callback_res.error_code == ERR_CODE.ERR_DETECT_QUEUE_FULL:
                        return
                    real_callback.onScanResult(seq, file_path, callback_res)
            callback = AsyncTaskCallback()
        while True:
            result = detector.detect(path, timeout_ms, callback)
            if result != ERR_CODE.ERR_DETECT_QUEUE_FULL.value:
                break
            if wait_if_queuefull is False:
                break
            detector.waitQueueAvailable(-1)
        
        return result   


    """
    格式化检测结果
    @param result 检测结果对象
    @return 格式化后的字符串
    """
    @staticmethod
    def formatDetectResult(result):
        if result.isSucc():
            info = result.getDetectResultInfo()
            msg = "[DETECT RESULT] [SUCCEED] md5: {}, time: {}, result: {}, score: {}".format(info.md5,
                info.time, info.result, info.score)
            vinfo = info.getVirusInfo()
            if vinfo is not None:
                msg += ", virus_type: {}, ext_info: {}".format(vinfo.virus_type, vinfo.ext_info)
            return msg
        
        info = result.getErrorInfo()
        msg = "[DETECT RESULT] [FAIL] md5: {}, time: {}, error_code: {}, error_message: {}".format(info.md5,
            info.time, info.error_code, info.error_string)
        return msg
        
        

    """
    同步检测目录或文件
    @param path 指定路径，可以是文件或者目录。目录的话就会递归遍历
    @param is_sync 是否使用同步接口，推荐使用异步。 True是同步，False是异步
    """
    def detectDirOrFileSync(self, detector, path, timeout_ms, result_map):
        abs_path = os.path.abspath(path)
        if os.path.isdir(abs_path):
            sub_files = os.listdir(abs_path)
            if len(sub_files) == 0:
                return
            for sub_file in sub_files:
                sub_path = os.path.join(abs_path, sub_file)
                self.detectDirOrFileSync(detector, sub_path, timeout_ms, result_map)
            return
        
        elif os.path.isfile(abs_path):
            print("[detectFileSync] [BEGIN] queueSize: {}, path: {}, timeout: {}".format(
                detector.getQueueSize(), abs_path, timeout_ms))
            res = self.detectFileSync(detector, abs_path, timeout_ms, True)
            print("                 [ END ] {}".format(self.formatDetectResult(res)))
            result_map[abs_path] = res
        
        return


    """
    异步检测目录或文件
    @param path 指定路径，可以是文件或者目录。目录的话就会递归遍历
    @param is_sync 是否使用同步接口，推荐使用异步。True是同步， False是异步
    """
    def detectDirOrFile(self, detector, path, timeout_ms, callback):
        abs_path = os.path.abspath(path)
        if os.path.isdir(abs_path):
            sub_files = os.listdir(abs_path)
            if len(sub_files) == 0:
                return
            for sub_file in sub_files:
                sub_path = os.path.join(abs_path, sub_file)
                self.detectDirOrFile(detector, sub_path, timeout_ms, callback)
            return
        
        elif os.path.isfile(abs_path):
            seq = self.detectFile(detector, abs_path, timeout_ms, True, callback)
            print("[detectFile] [BEGIN] seq: {}, queueSize: {}, path: {}, timeout: {}".format(
                seq, detector.getQueueSize(), abs_path, timeout_ms))
            
        return     

    
    """
    开始对文件或目录进行检测
    @param path 指定路径，可以是文件或者目录。目录的话就会递归遍历
    @param is_sync 是否使用同步接口，推荐使用异步。 True是同步，False是异步
    """
    def scan(self, detector, path, detect_timeout_ms, is_sync):
        try:
            print("[SCAN] [START] path: {}, detect_timeout_ms: {}, is_sync: {}".format(path, detect_timeout_ms, is_sync))
            start_time = time.time()
            result_map = {}
            if is_sync:
                self.detectDirOrFileSync(detector, path, detect_timeout_ms, result_map)
            else:
                class AsyncTaskCallback(IDetectResultCallback):
                    def onScanResult(self, seq, file_path, callback_res):
                        print("[detectFile] [ END ] seq: {}, queueSize: {}, {}".format(seq,
                            detector.getQueueSize(), Sample.formatDetectResult(callback_res)))
                        result_map[file_path] = callback_res
                self.detectDirOrFile(detector, path, detect_timeout_ms, AsyncTaskCallback())

                # 等待任务完成
                detector.waitQueueEmpty(-1)
            
            used_time_ms = (time.time() - start_time) * 1000 
            print("[SCAN] [ END ] used_time: {}, files: {}".format(used_time_ms, len(result_map)))
            
            failed_count = 0
            white_count = 0
            black_count = 0
            for file_path, res in result_map.items():
                if res.isSucc():
                    if res.getDetectResultInfo().result == DetectResult.RESULT.RES_BLACK:
                        black_count += 1
                    else:
                        white_count += 1
                else:
                    failed_count += 1
            
            print("               fail_count: {}, white_count: {}, black_count: {}".format(
                failed_count, white_count, black_count))

        except Exception as e:
            print(traceback.format_exc(), file=sys.stderr)


    def main(self):
        # 获取检测器实例
        detector = OpenAPIDetector.get_instance()

        # 初始化
        init_ret = detector.init("<AccessKey ID>", "<AccessKey Secret>")
        print("INIT RET: {}".format(init_ret))

        # 自定义扫描参数
        is_sync_scan = False # 是异步检测还是同步检测。异步检测性能更好。False表示异步检测
        timeout_ms = 120000 # 单个样本检测时间，单位为毫秒
        path = "./test" # 待扫描的文件或目录

        # 启动扫描，直到扫描结束
        self.scan(detector, path, timeout_ms, is_sync_scan)

        # 反初始化
        print("Over.")
        detector.uninit()
        

if __name__ == "__main__":
    sample = Sample()
    sample.main()
