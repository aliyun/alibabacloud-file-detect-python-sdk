# -*- coding: utf-8 -*-
import os
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
        self.m_is_inited = False
        self.m_client = None
        self.m_client_opt = None
        self.m_queue = None

        self.__m_threadpool = None
        self.__m_counter = 0
        self.__m_rej_handler = None

        self.sync_obj = SyncObject()

    
    """
    检测器初始化
    @param accessKeyId
    @param accessKeySecret
    @return
    """
    def init(self, accessKeyId, accessKeySecret):
        if self.m_is_inited:
            return ERR_CODE.ERR_INIT
        
        config = open_api_models.Config(accessKeyId, accessKeySecret)
        config.endpoint = "tds.aliyuncs.com"
        self.m_client = Sas20181203Client(config)
        self.m_client_opt = util_models.RuntimeOptions()
        self.m_client_opt.connectTimeout = Config.HTTP_CONNECT_TIMEOUT
        self.m_client_opt.readTimeout = Config.HTTP_READ_TIMEOUT  

        class TaskRejectedExecutionHandler(RejectedExecutionHandler):
            def rejectedExecution(self, r, executor):
                if isinstance(r, ScanTask):
                    r.errorCallback(ERR_CODE.ERR_ABORT, None)
        self.__m_rej_handler = TaskRejectedExecutionHandler()
        
        self.m_queue = BlockingDeque()
        self.__m_threadpool = MiniThreadPoolExecutor(self.m_queue, Config.THREAD_POOL_SIZE)
        self.__m_threadpool.prestartAllThreads()
        self.__m_threadpool.setRejectedExecutionHandler(self.__m_rej_handler)
        
        self.__m_counter = 0
        self.__m_alive_task_num = 0
        self.m_is_inited = True
        return ERR_CODE.ERR_SUCC
    

    # 检测器反初始化
    def uninit(self):
        if self.m_is_inited is False:
            return
        
        self.m_is_inited = False
        self.__m_threadpool.shutdown()

        with self.sync_obj:
            self.__m_threadpool = None
            self.__m_rej_handler = None
            self.m_queue = None
            self.m_client = None
            self.m_client_opt = None
            self.__m_counter = None


    """
    同步文件检测
    @param file_path 待检测文件路径
    @param timeout 超时时长，单位毫秒， < 0 无限等待
    @param res 检测结果
    @throws Exception
    """    
    def detectSync(self, file_path, timeout):
        res = []
        res.append(DetectResult())
        detect_sync_obj = SyncObject()
        class SyncTaskCallback(IDetectResultCallback):
            def onScanResult(self, seq, file_path, callback_res):
                res[0] = callback_res
                with detect_sync_obj:
                    detect_sync_obj.notify()

        seq = self.detect(file_path, timeout, SyncTaskCallback())
        if seq > 0:
            try:
                with detect_sync_obj:
                    detect_sync_obj.wait()
            except Exception as e:
                pass
        return res[0]
    

    def check_counter(self):
        if self.__m_counter < 0:
            self.__m_counter = 1
        if self.__m_counter > math.pow(2, 31):
            self.__m_counter = 1
        return


    """
    异步文件检测
    @param file_path 待检测文件路径
    @param timeout 超时时长，单位毫秒， < 0 无限等待
    @param res 检测结果
    @return >0 发起检测成功，检测请求序列号 < 0 错误码，参见ERR_CODE
    """
    def detect(self, file_path, timeout, callback):
        if not os.path.isfile(file_path):
            file_size = -1
        else:
            file_size = os.path.getsize(file_path)
        task = ScanTask(file_path, file_size, timeout, callback)
        if not os.path.isfile(file_path):
            task.errorCallback(ERR_CODE.ERR_FILE_NOT_FOUND, None)
            return ERR_CODE.ERR_FILE_NOT_FOUND.value
        
        seq = 0
        try:
            if self.m_is_inited:
                with self.sync_obj:
                    if self.m_is_inited:
                        self.__m_counter += 1
                        self.check_counter()
                        task.setSeq(self.__m_counter)
                        if self.getQueueSize() >= Config.QUEUE_SIZE_MAX:
                            raise RuntimeError("Deque full")
                        task.setTaskCallback(self)
                        self.m_queue.addLast(task)
                        with self.m_queue:
                            self.m_queue.notify()
                        seq = task.getSeq()
        
        except RuntimeError as e:
            task.errorCallback(ERR_CODE.ERR_DETECT_QUEUE_FULL, None)
            return ERR_CODE.ERR_DETECT_QUEUE_FULL.value
        
        if seq <= 0:
            task.errorCallback(ERR_CODE.ERR_INIT, None)
            return ERR_CODE.ERR_INIT.value
        
        return seq


    def currentTimeMillis(self):
        return int(round(time.time() * 1000))

    """
    @brief 获取检测队列长度
    @return 检测队列长度
    """
    def getQueueSize(self):
        if self.m_is_inited:
            with self.sync_obj:
                if self.m_is_inited:
                    return self.__m_alive_task_num
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
            if self.getQueueSize() < Config.QUEUE_SIZE_MAX:
                code = ERR_CODE.ERR_SUCC
                break
            
            if timeout >= 0 and all_time >= timeout:
                break
            
            sleep_unit = 200
            if timeout >= 0 and timeout > all_time and (timeout-all_time<sleep_unit):
                sleep_unit = timeout - all_time
            start_time = self.currentTimeMillis()
            time.sleep(sleep_unit/1000.0)
            all_time += self.currentTimeMillis() - start_time
        
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
            start_time = self.currentTimeMillis()
            time.sleep(sleep_unit/1000.0)
            all_time += self.currentTimeMillis() - start_time
        return code

    
    def onTaskEnd(self, task):
        if self.m_is_inited:
            with self.sync_obj:
                if self.m_is_inited:
                    self.__m_alive_task_num -= 1
    

    def onTaskBegin(self, task):
        if self.m_is_inited:
            with self.sync_obj:
                if self.m_is_inited:
                    self.__m_alive_task_num += 1
