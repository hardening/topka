import sys
import os
import time

if __name__ == '__main__':
    i = 1
    
    displayfd = 4 
    startAt = 10

    while i < len(sys.argv):
        if sys.argv[i] == '-displayfd':
            items = sys.argv[i+1].split(':', 2)
            displayFd = int(items[0])
            startAt = int(items[1])
            i += 1
        
        i += 1

    print("fake Xogon: displayfd={0} startAt={1}".format(displayFd, startAt))
    
    os.makedirs("/tmp/.pipe", exist_ok=True)
    with open("/tmp/.pipe/ogon_{0}_X11".format(startAt), "w+") as _f:
        pass

    time.sleep(0.5)

    f = os.fdopen(displayFd, "w")
    f.write("{0}".format(startAt))
    f.close()
    
    time.sleep(60)
    