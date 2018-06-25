from twisted.internet import reactor, defer


def treat_response(v):
    def action_completed():
        d.callback("success callback")
        reactor.stop()
    
    if v % 2 == 1:
        d = defer.Deferred()
        reactor.callLater(1, action_completed)
        return d
    else:
        return "success direct"

def treat_result(v):
    print v
    return len(v)

def treat_len(i):
    print 'len is {0}'.format(i)
    

if __name__ == '__main__':
    ret = treat_response(1)
    if isinstance(ret, defer.Deferred):
        ret.addCallback(treat_result)
        ret.addCallback(treat_len)
    else:
        treat_result(ret)
        
    reactor.run()