# -*- coding: utf-8 -*-

class Config(object):
    def __init__(
            self, 
            thread_pool_size = 64, 
            queue_size_max = 200, 
            query_result_interval = 100,      
            request_too_frequently_sleep_time = 100,
            http_connect_timeout = 6000,
            http_read_timeout = 6000, 
            http_upload_timeout = 60000
        ):
        self.THREAD_POOL_SIZE = thread_pool_size # 线程池大小
        self.QUEUE_SIZE_MAX = queue_size_max # 队列最大个数
        self.QUERY_RESULT_INTERVAL = query_result_interval # 查询检测结果间隔时间，单位为毫秒
        self.REQUEST_TOO_FREQUENTLY_SLEEP_TIME = request_too_frequently_sleep_time # 单样本请求太过频繁时，需要休眠时间，单位为毫秒
        self.HTTP_CONNECT_TIMEOUT = http_connect_timeout # 与服务器的网络连接超时时间，单位为毫秒
        self.HTTP_READ_TIMEOUT = http_read_timeout # 建立连接后，等待服务器响应的超时时间，单位为毫秒
        self.HTTP_UPLOAD_TIMEOUT = http_upload_timeout # 上传文件超时时间，单位为毫秒
