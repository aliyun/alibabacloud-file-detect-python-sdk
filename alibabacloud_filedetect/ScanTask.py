# -*- coding: utf-8 -*-

import os
import time
import json
import hashlib
import requests
import traceback
from abc import ABCMeta, abstractmethod
from alibabacloud_sas20181203 import models as sas_20181203_models

from .DetectResult import DetectResult
from .ERR_CODE import ERR_CODE
from .Config import Config
from .MiniThreadPool import Runnable


class TaskCallback(metaclass=ABCMeta):
    @abstractmethod
    def onTaskEnd(self, task):
        pass
    
    @abstractmethod
    def onTaskBegin(self, task):
        pass


class ScanTask(Runnable):
    GET_RESULT_FAIL = 1000 # 获取结果失败，未找到文件推送记录或者检测结果已过期
    REQUEST_TOO_FREQUENTLY = 2000 # 请求太频繁，请稍后再试
    HAS_EXCEPTION = -1 # 存在异常
    IS_OK = 0
    IS_BLACK = 1 # 可疑文件
    IS_DETECTING = 3 # 检测中，请等待
    

    def __init__(self, file_path, size, timeout, callback):
        self.__m_seq = 0
        self.__m_path = file_path
        self.__m_size = size
        self.__m_timeout = timeout
        self.__m_callback = callback
        self.__m_result = DetectResult()
        
        self.__m_start_time = self.currentTimeMillis()
        self.__m_last_time = 0

        self.__m_taskCallback = None

    
    def setSeq(self, seq):
        self.__m_seq = seq


    def getSeq(self):
        return self.__m_seq


    def setTaskCallback(self, callback):
        self.__m_taskCallback = callback
        if self.__m_taskCallback is not None:
            self.__m_taskCallback.onTaskBegin(self)
        

    def run(self):
        from .OpenAPIDetector import OpenAPIDetector
        # 缓存对象
        detector = OpenAPIDetector.get_instance()

        client = detector.m_client
        client_opt = detector.m_client_opt

        queue = detector.m_queue
        if detector.m_is_inited is False or client is None or queue is None:
             self.errorCallback(ERR_CODE.ERR_INIT, None)
             return
        

        # 判断是否已超时
        if self.__checkTimeout():
            return
        
        
        # 计算文件md5
        if self.__m_result.md5 is None:
            self.__m_result.md5 = self.__calcMd5(self.__m_path)
            if self.__m_result.md5 is None:
                self.errorCallback(ERR_CODE.ERR_FILE_NOT_FOUND, None)
                return
        

        # 如果距离上次查询过短，则需要等待一会
        if self.currentTimeMillis() - self.__m_last_time < Config.QUERY_RESULT_INTERVAL:
            with queue:
                queue.wait(Config.QUERY_RESULT_INTERVAL/1000.0)
            if self.currentTimeMillis() - self.__m_last_time < Config.QUERY_RESULT_INTERVAL:
                # 时间不够就放到队列里去
                queue.addLast(self)
                return

        # 更新时间戳
        self.__m_last_time = self.currentTimeMillis()

        # 获取扫描结果
        result_info = None
        while True:
            result_info = self.__getResultByAPI(client, client_opt, self.__m_result.md5)
            if result_info.result != self.REQUEST_TOO_FREQUENTLY:
                break
            self.__needSleep(Config.REQUEST_TOO_FREQUENTLY_SLEEP_TIME) # 请求太过频繁，需要休眠
            # 判断是否已超时
            if self.__checkTimeout():
                return
        
        if result_info.result == self.HAS_EXCEPTION:
            return # 出错，退出
        elif result_info.result == self.GET_RESULT_FAIL:
            # 没有结果，则尝试上传文件
            detect_ret = 0
            while True:
                detect_ret = self.__uploadAndDetectByAPI(client, client_opt, self.__m_path, self.__m_result.md5)
                if detect_ret != self.REQUEST_TOO_FREQUENTLY:
                    break
                
                self.__needSleep(Config.REQUEST_TOO_FREQUENTLY_SLEEP_TIME) # 请求太过频繁，需要休眠
                if self.__checkTimeout():
                    return

            if detect_ret == self.HAS_EXCEPTION: # 出错，退出
                return
            queue.addLast(self) # 重新添加到队列，等待再次查询扫描结果
        elif result_info.result == self.IS_BLACK:
            self.okCallback(True, result_info) # 报黑
        elif result_info.result == self.IS_DETECTING: # 检测中，请等待
            queue.addLast(self)
        else:
            self.okCallback(False, result_info) # 其他结果均为白


    def currentTimeMillis(self):
        return int(round(time.time() * 1000))


    def errorCallback(self, errCode, errString):
        self.__m_result.error_code = errCode
        self.__m_result.error_string = errString
        self.__m_result.time =  self.currentTimeMillis() - self.__m_start_time
        if self.__m_taskCallback is not None:
            self.__m_taskCallback.onTaskEnd(self)
        if self.__m_callback is not None:
            self.__m_callback.onScanResult(self.__m_seq, self.__m_path, self.__m_result)
        


    def okCallback(self, is_black, result_info):
        self.__m_result.error_code = ERR_CODE.ERR_SUCC
        self.__m_result.result = DetectResult.RESULT.RES_BLACK if is_black else DetectResult.RESULT.RES_WHITE
        self.__m_result.time = self.currentTimeMillis() - self.__m_start_time
        self.__m_result.score = result_info.score
        self.__m_result.virus_type = result_info.virus_type
        self.__m_result.ext_info = result_info.ext
        if self.__m_taskCallback is not None:
            self.__m_taskCallback.onTaskEnd(self)
        if self.__m_callback is not None:
            self.__m_callback.onScanResult(self.__m_seq, self.__m_path, self.__m_result)
        
    
    def __checkTimeout(self):
        curr_time = self.currentTimeMillis()
        if self.__m_timeout >= 0:
            if curr_time - self.__m_start_time > self.__m_timeout:
                if self.__m_result.md5 is None:
                    self.errorCallback(ERR_CODE.ERR_TIMEOUT_QUEUE, None)
                else:
                    self.errorCallback(ERR_CODE.ERR_TIMEOUT, None)
                return True

        return False


    def __needSleep(self, ms):
        try:
            time.sleep(ms/1000.0)
        except Exception as e:
            pass


    def __calcMd5(self, path):
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as f:
            data = f.read()
        file_md5 = hashlib.md5(data).hexdigest()
        return file_md5


    class ResultInfo(object):
        
        def __init__(self):
            self.result = 0
            self.score = 0
            self.virus_type = None
            self.ext = None
        
        
        def init_result(self, result, score=0, virus_type=None, ext=None):
            self.result = result
            self.score = score
            self.virus_type = virus_type
            self.ext = ext
            return self


    def __getErrorMessage(self, name, code, msg):
        if hasattr(msg, "status_code"):
            if 400 <= msg.status_code < 500:
                msg = "{} Client Error: {} for url: {}".format(msg.status_code, msg.reason, msg.url)
            elif 500 <= msg.status_code < 600:
                msg = "{} Server Error: {} for url: {}".format(msg.status_code, msg.reason, msg.url)
            else:
                msg = "{} Network Error: {} for url: {}".format(msg.status_code, msg.reason, msg.url)

        res = {}
        res["action"] = name
        res["error_code"] = code
        res["error_message"] = msg
        return json.dumps(res, sort_keys=True, separators=(',', ':'))


    def __getResultByAPI(self, client, client_opt, md5):
        api_name = "GetFileDetectResult"
        try:
            hashKeyList = [md5]
            get_file_detect_result_request = sas_20181203_models.GetFileDetectResultRequest(hashKeyList, type=0)
            response = client.get_file_detect_result_with_options(get_file_detect_result_request, client_opt)
            org_result = response.body.result_list[0]
            score = org_result.score if org_result.score is not None else 0
            result = org_result.result if org_result.result is not None else 0
            result_info = self.ResultInfo().init_result(result, score, org_result.virus_type, org_result.ext)
            return result_info

        except Exception as error:
            if hasattr(error, "code"):
                if error.code == "GetResultFail":
                    return self.ResultInfo().init_result(self.GET_RESULT_FAIL)
                elif error.code == "RequestTooFrequently":
                    return self.ResultInfo().init_result(self.REQUEST_TOO_FREQUENTLY)
                elif error.code == "Throttling.User":
                    return self.ResultInfo().init_result(self.REQUEST_TOO_FREQUENTLY)
                else:
                    self.errorCallback(ERR_CODE.ERR_CALL_API, self.__getErrorMessage(api_name, error.code, error.message))
                    return self.ResultInfo().init_result(self.HAS_EXCEPTION)
            else:
                self.errorCallback(ERR_CODE.ERR_CALL_API, self.__getErrorMessage(api_name, "ERR_NETWORK", traceback.format_exc()))
                return self.ResultInfo().init_result(self.HAS_EXCEPTION)


    def __uploadAndDetectByAPI(self, client, client_opt, path, md5):
        api_name = ""
        api_callerr = ERR_CODE.ERR_CALL_API
        try:
            # 获取上传参数
            api_name = "CreateFileDetectUploadUrl"
            api_callerr = ERR_CODE.ERR_CALL_API
            hash_key_context_list_0 = sas_20181203_models.CreateFileDetectUploadUrlRequestHashKeyContextList(
                hash_key = md5,
                file_size = self.__m_size
            )
            create_file_detect_upload_url_request = sas_20181203_models.CreateFileDetectUploadUrlRequest(type=0, hash_key_context_list=[hash_key_context_list_0])
            response = client.create_file_detect_upload_url_with_options(create_file_detect_upload_url_request, client_opt)
            upload_url_response = response.body.upload_url_list[0]
            
            if not upload_url_response.file_exist:
                # 上传文件
                api_name = "UploadFile"
                api_callerr = ERR_CODE.ERR_UPLOAD
                upload_file_res = self.__uploadFile(path, upload_url_response.public_url, upload_url_response.context)
                    
            # 发起检测
            api_name = "CreateFileDetect"
            api_callerr = ERR_CODE.ERR_CALL_API
            create_file_detect_request = sas_20181203_models.CreateFileDetectRequest(
                type=0,
                hash_key=md5,
                oss_key=upload_url_response.context.oss_key
            )
            client.create_file_detect_with_options(create_file_detect_request, client_opt)

        except Exception as error:
            if hasattr(error, "code"):
                if error.code == "RequestTooFrequently":
                    return self.REQUEST_TOO_FREQUENTLY
                elif error.code == "Throttling.User":
                    return self.REQUEST_TOO_FREQUENTLY
                else:
                    self.errorCallback(api_callerr, self.__getErrorMessage(api_name, error.code, error.message))
                    return self.HAS_EXCEPTION
            elif hasattr(error, "response"):
                self.errorCallback(api_callerr, self.__getErrorMessage(api_name, "ERR_NETWORK", error.response))
                return self.HAS_EXCEPTION
            else:
                self.errorCallback(api_callerr, self.__getErrorMessage(api_name, "ERR_NETWORK", traceback.format_exc()))
                return self.HAS_EXCEPTION

        return self.IS_OK


    def __uploadFile(self, path, url, context):
        if not os.path.isfile(path):
            raise Exception("File {} not found".format(path))
            return False
        files = {"file": open(path, "rb")}
        data = {
            'key': context.oss_key,
            'policy': context.policy,
            'OSSAccessKeyId': context.access_id,
            'success_action_status': '200',
            'Signature': context.signature
        }
        response = requests.post(url, files=files, data=data)
        if response.status_code == 200:
            return True
        else:
            response.raise_for_status()
            return False
