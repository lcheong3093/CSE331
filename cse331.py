import sys


class HTTP_Controller:
    def __init__(self):
        self.num = 0

    def request(self, flow):
        log = open("log.txt", "w")
        drop = False

        with open("./rules.txt", "r") as file:
            rules = file.readlines()
            for rule in rules:
                tmp = rule.split(" ") #remove comment
                parts = tmp.split(",")[0]

                # parts = [HEADER:____,CONTAINS:"______"]
                if(parts.__len__() == 2):
                    header = parts[0][8:]
                    contains = parts[1][11:-1]
                    user_agents = flow.request.headers[header]
                    if (contains in user_agents):
                        log.write("User-Agent attack")
                        drop = True

                # parts = [REQUEST_METHOD:____,PARAMETER:______,CONTAINS:"______"]
                if(parts.__len__() == 3):
                    method = flow.request.method
                    request_method = parts[0][15:]
                    parameter = parts[1][11:]
                    contains = parts[2][11:-1]

                    if (request_method == "GET"):
                        if (method == "GET"):
                            if(parameter == "*"):
                                for v in flow.request.query:
                                    if (contains in v):
                                        log.write("HTTP Method attack")
                                        drop = True
                            else:
                                if (contains) in flow.request.query[parameter]:
                                    log.write("HTTP Method attack")
                                    drop = True

                    if (method == "POST"):
                        if (request_method == "POST"):
                            if(parameter == "*"):
                                for v in flow.request.query:
                                    if (contains in v):
                                        log.write("HTTP Method attack")
                                        drop = True
                            else:
                                if (contains) in flow.request.query[parameter]:
                                    log.write("HTTP Method attack")
                                    drop = True

        if(drop):
            flow.kill()

        log.close()

addons = [HTTP_Controller()]
