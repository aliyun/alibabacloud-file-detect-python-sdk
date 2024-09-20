# -*- coding: utf-8 -*-
import os
import re
import sys
import math
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from alibabacloud_sas20181203.client import Client as Sas20181203Client
from alibabacloud_tea_util import models as util_models
from alibabacloud_tea_openapi import models as open_api_models

from .ERR_CODE import ERR_CODE
from .Config import Config
from .MiniThreadPool import BlockingDeque, SyncObject, RejectedExecutionHandler, MiniThreadPoolExecutor
from .IDetectResultCallback import IDetectResultCallback
from .DetectResult import DetectResult
from .ScanTask import ScanTask, TaskCallback
from .Decompress import Decompress


class OpenAPIDetector(TaskCallback):
    _instance_lock = threading.Lock()
    
    # 获取单例检测器
    @classmethod
    def get_instance(cls, *args, **kwargs):
        return OpenAPIDetector(*args, **kwargs)


    def __new__(cls, *args, **kwargs):
        if hasattr(cls, "_instance"):
            return cls._instance
        with cls._instance_lock:
            if not hasattr(cls, "_instance"):
                tmp_instance = object.__new__(cls, *args, **kwargs)
                tmp_instance.__init()
                cls._instance = tmp_instance
        return cls._instance


    def __init__(self):
        pass


    def __init(self):
        self.is_inited = False
        self.client = None
        self.client_opt = None
        self.queue = None

        self.__threadpool = None
        self.__counter = 0
        self.__rej_handler = None
        self.__decompress = None
        self.__config = Config()
        self.__alive_task_num = 0

        self.sync_obj = SyncObject()

    
    """
    检测器初始化
    @param accessKeyId
    @param accessKeySecret
    @param securityToken 可选
    @param region 可选
    @return
    """
    def init(self, accessKeyId, accessKeySecret, securityToken=None, regionId="cn-shanghai"):
        if self.is_inited:
            return ERR_CODE.ERR_INIT
        
        if securityToken is None:
            openapi_config = open_api_models.Config(accessKeyId, accessKeySecret)
        else:
            openapi_config = open_api_models.Config(accessKeyId, accessKeySecret, securityToken)
        
        openapi_config.endpoint = "tds.aliyuncs.com"
        if "-" in regionId:
            if regionId.startswith("cn-"):
                openapi_config.endpoint = "tds.aliyuncs.com"
            else:
                openapi_config.endpoint = "tds.ap-southeast-1.aliyuncs.com"

        self.client = Sas20181203Client(openapi_config)
        self.client_opt = util_models.RuntimeOptions()
        self.client_opt.connectTimeout = self.__config.HTTP_CONNECT_TIMEOUT
        
        self.client_opt.readTimeout = self.__config.HTTP_READ_TIMEOUT

        class TaskRejectedExecutionHandler(RejectedExecutionHandler):
            def rejectedExecution(self, r, executor):
                if isinstance(r, ScanTask):
                    r.errorCallback(ERR_CODE.ERR_ABORT, None)
        self.__rej_handler = TaskRejectedExecutionHandler()
        
        self.queue = BlockingDeque()
        self.__threadpool = MiniThreadPoolExecutor(self.queue, self.__config.THREAD_POOL_SIZE)
        self.__threadpool.prestartAllThreads()
        self.__threadpool.setRejectedExecutionHandler(self.__rej_handler)
        
        self.__counter = 0
        self.__alive_task_num = 0
        self.is_inited = True
        return ERR_CODE.ERR_SUCC
    

    # 检测器反初始化
    def uninit(self):
        if self.is_inited is False:
            return
        
        self.is_inited = False
        self.__threadpool.shutdown()

        with self.sync_obj:
            self.__threadpool = None
            self.__rej_handler = None
            self.queue = None
            self.client = None
            self.client_opt = None
    
    """
    初始化全局配置参数
    @param thread_pool_size 线程池大小，可选
    @param queue_size_max 查询检测结果间隔时间，单位为毫秒，可选
    @param request_too_frequently_sleep_time 单样本请求太过频繁时，需要休眠时间，单位为毫秒，可选
    @param http_connect_timeout 建立连接后，等待服务器响应的超时时间，单位为毫秒，可选
    @param http_read_timeout 建立连接后，等待服务器响应的超时时间，单位为毫秒，可选
    @param http_upload_timeout 上传文件超时时间，单位为毫秒，可选
    """
    def initConfig(
            self, 
            thread_pool_size = 64, 
            queue_size_max = 200, 
            query_result_interval = 100,      
            request_too_frequently_sleep_time = 100,
            http_connect_timeout = 6000,
            http_read_timeout = 6000, 
            http_upload_timeout = 60000
        ):
        if self.is_inited is True:
            return ERR_CODE.ERR_INIT
        self.__config = Config(
            thread_pool_size = thread_pool_size,
            queue_size_max = queue_size_max,
            query_result_interval = query_result_interval,
            request_too_frequently_sleep_time = request_too_frequently_sleep_time,
            http_connect_timeout = http_connect_timeout,
            http_read_timeout = http_read_timeout,
            http_upload_timeout = http_upload_timeout
        )
        return ERR_CODE.ERR_SUCC

    """
    初始化解压缩配置参数
    @param open 是否识别压缩文件并解压
    @param maxlayer 最大解压层数，open参数为true时生效
    @param maxfilecount 最大解压文件数，open参数为true时生效
    """
    def initDecompress(self, open, maxlayer, maxfilecount):
        if self.is_inited is False:
            return ERR_CODE.ERR_INIT
        self.__decompress = Decompress(open, maxlayer, maxfilecount)
        return ERR_CODE.ERR_SUCC


    """
    同步文件检测
    @param file_path 待检测文件路径
    @param timeout 超时时长，单位毫秒， < 0 无限等待
    """
    def detectSync(self, file_path, timeout):
        return self.__internalDetectSync(file_path, None, timeout)
    

    """
    同步URL文件检测
    @param url 待检测文件下载链接URL
    @param md5 文件md5
	@param timeout 超时时长，单位毫秒， < 0 无限等待
	@return res 检测结果
    """
    def detectUrlSync(self, url, md5, timeout):
        return self.__internalDetectSync(url, md5, timeout)


    def __internalDetectSync(self, file_path, md5, timeout):
        res = []
        res.append(DetectResult())
        detect_sync_obj = SyncObject()
        class SyncTaskCallback(IDetectResultCallback):
            def onScanResult(self, seq, file_path, callback_res):
                res[0] = callback_res
                with detect_sync_obj:
                    detect_sync_obj.notify()
        
        seq = 0
        if md5 is None:
            # 本地文件检测
            seq = self.detect(file_path, timeout, SyncTaskCallback())
        else:
            # URL文件检测
            seq = self.detectUrl(file_path, md5, timeout, SyncTaskCallback())
        if seq > 0:
            try:
                with detect_sync_obj:
                    detect_sync_obj.wait()
            except Exception as e:
                pass
        return res[0]
    

    """
    异步文件检测
    @param file_path 待检测文件路径
    @param timeout 超时时长，单位毫秒， < 0 无限等待
    @param callback 检测结果
    @return >0 发起检测成功，检测请求序列号 < 0 错误码，参见ERR_CODE
    """
    def detect(self, file_path, timeout, callback):
        file_size = self.__get_filesize(file_path)
        task = ScanTask()
        task.initScanFile(file_path, file_size, timeout, callback, self.__decompress, self.__config)
        if file_size < 0:
            task.errorCallback(ERR_CODE.ERR_FILE_NOT_FOUND, file_path)
            return ERR_CODE.ERR_FILE_NOT_FOUND.value
        return self.__internalDetect(task)

    
    """
    异步URL文件检测
    @param url 待检测文件下载链接URL
	@param md5 文件md5
	@param timeout 超时时长，单位毫秒， < 0 无限等待
	@param callback 检测结果
	@return >0 发起检测成功，检测请求序列号 < 0 错误码，参见ERR_CODE
    """
    def detectUrl(self, url, md5, timeout, callback):
        if md5 is not None:
            # 转小写
            md5 = md5.lower()
        task = ScanTask()
        task.initScanUrl(url, md5, timeout, callback, self.__decompress, self.__config)
        if md5 is None or len(md5) != 32 or re.match(r'^[a-f0-9]{32}$', md5) is None:
            task.errorCallback(ERR_CODE.ERR_MD5, md5)
            return ERR_CODE.ERR_MD5.value
        if url is None:
            task.errorCallback(ERR_CODE.ERR_URL, url)
            return ERR_CODE.ERR_URL.value
        # 检查url的合法性
        if self.__is_valid_url(url) is False:
            task.errorCallback(ERR_CODE.ERR_URL, "Malformed URL: {}".format(url))
            return ERR_CODE.ERR_URL.value
        return self.__internalDetect(task)
    

    def __internalDetect(self, task):
        seq = 0
        try:
            if self.is_inited:
                with self.sync_obj:
                    if self.is_inited:
                        self.__counter += 1
                        self.__check_counter()
                        task.setSeq(self.__counter)
                        if self.getQueueSize() >= self.__config.QUEUE_SIZE_MAX:
                            raise RuntimeError("Deque full")
                        task.setTaskCallback(self)
                        self.queue.addLast(task)
                        with self.queue:
                            self.queue.notify()
                        seq = task.getSeq()
        except RuntimeError as e:
            task.errorCallback(ERR_CODE.ERR_DETECT_QUEUE_FULL, None)
            return ERR_CODE.ERR_DETECT_QUEUE_FULL.value
        
        if seq <= 0:
            task.errorCallback(ERR_CODE.ERR_INIT, None)
            return ERR_CODE.ERR_INIT.value
        return seq


    """
    @brief 获取检测队列长度
    @return 检测队列长度
    """
    def getQueueSize(self):
        if self.is_inited:
            with self.sync_obj:
                if self.is_inited:
                    return self.__alive_task_num
        return 0

    
    """
    @brief 等待队列空间可用（可进行新样本插入）
    @param timeout 超时时长，单位毫秒， < 0 无限等待
    @return ERR_SUCC 成功，队列已有可用空间 ERR_TIMEOUT 失败，队列仍然满
    """
    def waitQueueAvailable(self, timeout):
        code = ERR_CODE.ERR_TIMEOUT
        all_time = 0
        while True:
            if self.getQueueSize() < self.__config.QUEUE_SIZE_MAX:
                code = ERR_CODE.ERR_SUCC
                break
            
            if timeout >= 0 and all_time >= timeout:
                break
            
            sleep_unit = 200
            if timeout >= 0 and timeout > all_time and (timeout-all_time<sleep_unit):
                sleep_unit = timeout - all_time
            start_time = self.__current_time_millis()
            time.sleep(sleep_unit/1000.0)
            all_time += self.__current_time_millis() - start_time
        
        return code
    

    """
    @brief 等待队列为空
    @param timeout 超时时长，单位毫秒， < 0 无限等待
    @return ERR_SUCC 成功，队列已空，所有检测工作完成 ERR_TIMEOUT 失败，队列中仍然有检测任务
    """
    def waitQueueEmpty(self, timeout):
        code = ERR_CODE.ERR_TIMEOUT
        all_time = 0
        while True:
            if self.getQueueSize() == 0:
                code = ERR_CODE.ERR_SUCC
                break

            if timeout >=0 and all_time >= timeout:
                break

            sleep_unit = 200
            if timeout >= 0 and timeout > all_time and (timeout-all_time<sleep_unit):
                sleep_unit = timeout - all_time
            start_time = self.__current_time_millis()
            time.sleep(sleep_unit/1000.0)
            all_time += self.__current_time_millis() - start_time
        return code
    

    def onTaskEnd(self, task):
        if self.is_inited:
            with self.sync_obj:
                if self.is_inited:
                    self.__alive_task_num -= 1
    

    def onTaskBegin(self, task):
        if self.is_inited:
            with self.sync_obj:
                if self.is_inited:
                    self.__alive_task_num += 1


    def __current_time_millis(self):
        return int(round(time.time() * 1000))


    def __get_filesize(self, path):
        if not os.path.isfile(path):
            return -1
        else:
            return os.path.getsize(path)

    
    def __is_valid_url(self, url):
        try:
            if sys.version_info[0] == 3:
                from urllib.parse import urlparse
            else:
                from urlparse import urlparse
            parsed = urlparse(url)
            return (bool(parsed.scheme) and bool(parsed.netloc))
        except Exception as e:
            return False

    
    def __check_counter(self):
        if self.__counter < 0:
            self.__counter = 1
        if self.__counter > math.pow(2, 31):
            self.__counter = 1
        return
