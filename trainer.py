from mitmproxy.io import FlowReader
from Request_Constraint import Request_Constraints
#Source: https://avilpage.com/2018/08/parsing-and-transforming-mitmproxy-request-flows.html

filename = 'dump.txt'
request_obj_list = []
with open(filename, 'rb') as fp:
    reader = FlowReader(fp)
    #param_length_per_visit = {}
    #max_param = 0
    #param_chars = {}

    for flow in reader.stream():
        request = flow.request
        url = request.url.split("?")[0]

        #Check if an Request_Constraints obj exists already for the url
        exists = False
        request_obj = None
        idx = -1
        for i in range(len(request_obj_list)):
            tmp = request_obj_list[i].url
            if(request_obj_list[i].url == url):
                exists = True
                idx = i
                request_obj = request_obj_list[i]

        if(not exists):
            request_obj = Request_Constraints(url)
            #check GET # of params
            if(request.method == "GET"):
                request_obj.max_params = len(request.query)
                for k, v in request.query.items():
                    request_obj.param_length_per_visit[k] = [len(v)]
                    request_obj.param_chars[k] = v
            else:
                tmp = request.get_text().split("&")
                params = {}
                for line in tmp:
                    pairs = line.split("=")
                    params[pairs[0]] = pairs[1]

                if(len(params) > request_obj.max_params):
                    request_obj.max_params = len(params)
                for k, v in params.items():
                    request_obj.param_length_per_visit[k] = [len(v)]
                    request_obj.param_chars[k] = v

            request_obj_list.append(request_obj)
        else:
            #check GET # of params
            if(request.method == "GET"):
                if(len(request.query) > request_obj.max_params):
                    max_param = len(request.query)
                for k, v in request.query.items():
                    if(k in request_obj.param_length_per_visit.keys()):
                        request_obj.param_length_per_visit[k].append(len(v))
                        request_obj.param_chars[k] += v
                    else:
                        request_obj.param_length_per_visit[k] = [len(v)]
                        request_obj.param_chars[k] = v
            else:
                tmp = request.get_text().split("&")
                params = {}
                for line in tmp:
                    pairs = line.split("=")
                    params[pairs[0]] = pairs[1]

                if(len(params) > request_obj.max_params):
                    request_obj.max_params = len(params)
                for k, v in params.items():
                    if(k in request_obj.param_length_per_visit.keys()):
                        request_obj.param_length_per_visit[k].append(len(v))
                        request_obj.param_chars[k] += v
                    else:
                        request_obj.param_length_per_visit[k] = [len(v)]
                        request_obj.param_chars[k] = v
        
            request_obj_list[idx] = request_obj

with open('profile.txt', 'w') as file:
    for obj in request_obj_list:
        file.write(obj.url)
        file.write(" ")
        file.write(str(obj.max_params))
        file.write(" ")
        tmp = ""
        for k, v in obj.param_chars.items():
            #value_str = ",".join(str(i) for i in v)
            tmp += str(k) + ":" + v + ";"
        tmp = tmp[:-1]
        file.write(tmp)
        file.write(" ")
        tmp = ""
        for k,v in obj.avg_param().items():
            tmp += str(k) + ":" + str(v) + ';'
        tmp = tmp[:-1]
        file.write(tmp)
        file.write(" ")
        tmp = ""
        for k, v in obj.std_param().items():
            tmp += str(k) + ":" + str(v) + ';'
        tmp = tmp[:-1]
        file.write(tmp)
        file.write("\n")

