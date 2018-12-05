class Request_Constraints:
    def __init__(self, url, max_params=0, param_chars=None, param_length_per_visit=None):
        self.url = url
        self.max_params = max_params #use to see maximum params
        if(param_chars is None):
            param_chars = {} #key, string, used to see character set of paramters
        self.param_chars = param_chars
        if(param_length_per_visit is None):
            param_length_per_visit = {}
        self.param_length_per_visit = param_length_per_visit #key, [int]; user to see

    def avg_param(self):
        answer = {}
        for k,v in self.param_length_per_visit.items():
            total = 0
            for i in v:
                total += i
            answer[k] = total / v.__len__()

        return answer

    def std_param(self):
        avg = self.avg_param()
        answer = {}
        for k,v in self.param_length_per_visit.items():
            total = 0
            for i in range(v.__len__()):
                total += (v[i] - avg[k]) ** 2
            answer[k] = total / v.__len__()

        return answer


