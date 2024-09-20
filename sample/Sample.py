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
    同步检测URL文件接口
    @param detector 检测器对象
	@param url 待检测的文件URL
	@param md5 待检测的文件md5
	@param timeout_ms 设置超时时间，单位为毫秒
	@param wait_if_queuefull 如果检测队列满了，false表示不等待直接返回错误，true表示一直等待直到队列不满时
    """
    def detectUrlSync(self, detector, url, md5, timeout_ms, wait_if_queuefull):
        if detector is None or url is None or md5 is None:
            return None
        result = None
        while True:
            result = detector.detectUrlSync(url, md5, timeout_ms)
            if result is None:
                break
            if result.error_code != ERR_CODE.ERR_DETECT_QUEUE_FULL:
                break
            if wait_if_queuefull is False:
                break
            detector.waitQueueAvailable(-1)
        return result


    """
    异步检测URL文件接口
	@param detector 检测器对象
	@param url 待检测的文件URL
	@param md5 待检测的文件md5
	@param timeout_ms 设置超时时间，单位为毫秒
	@param wait_if_queuefull 如果检测队列满了，false表示不等待直接返回错误，true表示一直等待直到队列不满时
	@param callback 结果回调函数
    """
    def detectUrl(self, detector, url, md5, timeout_ms, wait_if_queuefull, callback):
        if detector is None or url is None or md5 is None or callback is None:
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
            result = detector.detectUrl(url, md5, timeout_ms, callback)
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
        msg = ""
        if result.isSucc():
            info = result.getDetectResultInfo()
            msg = "[DETECT RESULT] [SUCCEED] {}".format(Sample.formatDetectResultInfo(info))
            if info.compresslist is not None:
                idx = 1
                for comp_res in info.compresslist:
                    msg += "\n\t\t\t [COMPRESS FILE] [IDX:{}] {}".format(idx, Sample.formatCompressFileDetectResultInfo(comp_res))
                    idx += 1
        else:
            info = result.getErrorInfo()
            msg = "[DETECT RESULT] [FAIL] md5: {}, time: {}, error_code: {}, error_message: {}".format(info.md5,
                info.time, info.error_code.name, info.error_string)
        return msg


    @staticmethod
    def formatDetectResultInfo(info):
        msg = "MD5: {}, TIME: {}, RESULT: {}, SCORE: {}".format(info.md5, info.time, info.result.name, info.score)
        if info.compresslist is not None:
            msg += ", COMPRESS_FILES: {}".format(len(info.compresslist))
        vinfo = info.getVirusInfo()
        if vinfo is not None:
            msg += ", VIRUS_TYPE: {}, EXT_INFO: {}".format(vinfo.virus_type, vinfo.ext_info)
        return msg


    @staticmethod
    def formatCompressFileDetectResultInfo(info):
        msg = "PATH: {}, \t\t RESULT: {}, SCORE: {}".format(info.path, info.result.name, info.score)
        vinfo = info.getVirusInfo()
        if vinfo is not None:
            msg += ", VIRUS_TYPE: {}, EXT_INFO: {}".format(vinfo.virus_type, vinfo.ext_info)
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
        
        print("[detectFileSync] [BEGIN] queueSize: {}, path: {}, timeout: {}".format(
            detector.getQueueSize(), abs_path, timeout_ms))
        res = self.detectFileSync(detector, abs_path, timeout_ms, True)
        print("                 [ END ] {}".format(Sample.formatDetectResult(res)))
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
                # 等待任务执行完成
                detector.waitQueueEmpty(-1)
            
            used_time_ms = (time.time() - start_time) * 1000 
            print("[SCAN] [ END ] used_time: {}, files: {}".format(int(used_time_ms), len(result_map)))
            
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

        # 设置全局配置，需要在初始化前调用（该操作可选，默认配置如下）
        thread_pool_size = 64 # 线程池大小，默认为64
        queue_size_max = 200 # 队列最大个数，默认为200
        query_result_interval = 100 # 查询检测结果间隔时间，单位为毫秒，默认为100，避免qps过高
        request_too_frequently_sleep_time = 100 # 单样本请求太过频繁时，需要休眠时间，单位为毫秒，默认为100
        http_connect_timeout = 6000 # 与服务器的网络连接超时时间，单位为毫秒，默认为6000
        http_read_timeout = 6000 # 建立连接后，等待服务器响应的超时时间，单位为毫秒，默认为6000
        http_upload_timeout = 60000 # 上传文件超时时间，单位为毫秒，默认为60000
        # 该函数的所有参数均为可选参数，可通过key=value的形式设置部分参数，以下示例为设置全部参数
        initcon_ret = detector.initConfig(
            thread_pool_size=thread_pool_size, 
            queue_size_max=queue_size_max, 
            query_result_interval=query_result_interval,
            request_too_frequently_sleep_time=request_too_frequently_sleep_time,
            http_connect_timeout=http_connect_timeout,
            http_read_timeout=http_read_timeout,
            http_upload_timeout=http_upload_timeout)
        print("INIT_CONFIG RET: {}".format(initcon_ret.name))

        # 初始化，初始化给出两种示例，使用时根据实际情况按需选择其中一种方式初始化
        if True:
            # 初始化示例1，可通过AccessKey ID和AccessKey Secret的方式接入，第3个参数regionId为可用区ID（例如cn-shanghai），该参数为可选参数，可省略
            init_ret = detector.init("<AccessKey ID>", "<AccessKey Secret>", regionId="<your regionId>")
            print("INIT RET: {}".format(init_ret.name))
        else:
            # 初始化示例2，可通过阿里云STS Token方式接入，第4个参数regionId为可用区ID（例如cn-shanghai），该参数是可选参数，可省略
            init_ret = detector.init("<AccessKey ID>", "<AccessKey Secret>", "<Security Token>", regionId="<Your regionId>")
            print("INIT RET: {}".format(init_ret.name))

        # 设置解压缩参数(可选，默认不解压压缩包)
        decompress = True # 是否识别压缩文件并解压，默认为false
        decompressMaxLayer = 5 # 最大解压层数，decompress参数为true时生效
        decompressMaxFileCount = 1000 # 最大解压文件数，decompress参数为true时生效
        initdec_ret = detector.initDecompress(decompress, decompressMaxLayer, decompressMaxFileCount)
        print("INIT_DECOMPRESS RET: {}".format(initdec_ret.name))

        if True:
            # 示例用法1：扫描本地目录或文件
            is_sync_scan = False # 是异步检测还是同步检测。异步检测性能更好。False表示异步检测
            timeout_ms = 500000 # 单个样本检测时间，单位为毫秒
            path = "test.bin" # 待扫描的文件或目录
            # 启动扫描，直到扫描结束
            self.scan(detector, path, timeout_ms, is_sync_scan)

        if True:
            # 示例用法2：扫描URL文件
            timeout_ms = 500000
            url = "https://xxxxxxxx.oss-cn-hangzhou-1.aliyuncs.com/xxxxx/xxxxxxxxxxxxxx?Expires=1671448125&OSSAccessKeyId=xxx" # 待扫描的URL文件
            md5 = "a767ffc59d93125c7505b6e21d000000"
            # 同步扫描。如果需要异步扫描，调用detectUrl接口
            print("[detectUrlSync] [BEGIN] URL: {}, MD5: {}, TIMEOUT: {}".format(url, md5, timeout_ms))
            result = self.detectUrlSync(detector, url, md5, timeout_ms, True)
            print("[detectUrlSync] [ END ] {}".format(Sample.formatDetectResult(result)))

        # 反初始化
        print("Over.")
        detector.uninit()
        

if __name__ == "__main__":
    sample = Sample()
    sample.main()
