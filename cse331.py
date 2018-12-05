from Request_Constraint import Request_Constraints
import os
from datetime import datetime

class HTTP_Controller:
    def __init__(self):
        self.num = 0

    def request(self, flow):
        if(os.path.exists("log.txt")):
            append_write = 'a'
        else:
            append_write = 'w'
        log = open("log.txt", append_write)
        log.write(str(datetime.now()) + "\n")
        log.write("-" * 30 + '\n')
        drop = False

        #Check for malicious signatures
        with open("./rules.txt", "r") as file:
            rules = file.readlines()
            for rule in rules:
                tmp = rule.split("\t")[0] #remove comment
                tmp = tmp.rstrip(" ")
                parts = tmp.split(',')

                # parts = [HEADER:____,CONTAINS:"______"]
                if(parts.__len__() == 2):
                    
                    header = parts[0][7:]
                    contains = parts[1][10:-1]
                    user_agents = flow.request.headers[header]
                    if (contains in user_agents):
                        log.write("User-Agent attack\n")
                        drop = True

                # parts = [REQUEST_METHOD:____,PARAMETER:______,CONTAINS:"______"]
                if(parts.__len__() == 3):
                    method = flow.request.method
                    request_method = parts[0][15:]
                    parameter = parts[1][10:]
                    contains = parts[2][10:-1]

                    if (request_method == "GET"):
                        if (method == "GET"):
                            if(parameter == "*"):
                                #print(flow.request.query.values())
                                for v in flow.request.query.values():
                                    if (contains in v):
                                        log.write("HTTP Method attack\n")
                                        drop = True
                            else:
                                if (contains) in flow.request.query[parameter]:
                                    log.write("HTTP Method attack\n")
                                    drop = True

                    if (request_method == "POST"):
                        if (method == "POST"):
                            #Converting text into k,v pairs
                            tmp = flow.request.get_text().split("&")
                            #if not tmp[0] is [""]:
                            post_param = {}
                            for line in tmp:
                                pairs = line.split("=")
                                post_param[pairs[0]] = pairs[1].replace("%2F", "/")

                            if(parameter == "*"):
                                for v in post_param.values():
                                    if (contains in v):
                                        log.write("HTTP Method attack\n")
                                        drop = True
                            else:
                                if (parameter in post_param.keys() and contains in post_param[parameter]):
                                    log.write("HTTP Method attack\n")
                                    drop = True

        #Check for anomalies
        request_obj_list = []
        with open("profile.txt", 'r') as file:
            lines = file.readlines()
            for line in lines:
                profile = line.split(" ")
                request_obj = Request_Constraints(profile[0])
                request_obj.max_params = int(profile[1])
                if (profile[2] != ""):
                    params = profile[2].split(";")  # char set
                    params2 = profile[3].split(";")  # avg
                    params3 = profile[4].split(";")  # std
                    param_avg = {}
                    param_std = {}
                    param_char_set = {}
                    for i in range(len(params)):
                        tmp = params[i].split(":")
                        tmp2 = params2[i].split(":")
                        tmp3 = params3[i].split(":")
                        param_char_set[tmp[0]] = tmp[1]
                        param_avg[tmp2[0]] = float(tmp2[1])
                        param_std[tmp3[0]] = float(tmp3[1])
                    request_obj.param_chars = param_char_set
                    request_obj.avg = param_avg
                    request_obj.std = param_std
                request_obj_list.append(request_obj)

        request_obj = None
        url = flow.request.url.split("?")[0]
        for i in range(len(request_obj_list)):
            tmp = request_obj_list[i].url
            if (tmp == url):
                request_obj = request_obj_list[i]
        if(not request_obj is None):
            if(flow.request.method == "GET"):
                query = flow.request.query
            else:
                tmp = flow.request.get_text().split("&")
                # if not tmp[0] is [""]:
                query = {}
                for line in tmp:
                    pairs = line.split("=")
                    query[pairs[0]] = pairs[1].replace("%2F", "/")
            if(len(query) > request_obj.max_params):
                log.write('Number of parameters execeeded\n')
                drop = True
            else:
                for k,v in query.items():
                    if(len(v) > request_obj.avg[k] + (3 * request_obj.std[k]) or len(v) < request_obj.avg[k] - (3 * request_obj.std[k])):
                        log.write('Unexpected length of character in parameter\n')
                        drop = True
                    for c in v:
                        if not c in request_obj.param_chars[k]:
                            log.write('Unexpected characters in parameter\n')
                            drop = True

        if(drop):
            flow.kill()

        log.close()

addons = [HTTP_Controller()]
