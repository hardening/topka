import os, os.path
import time

if __name__ == '__main__':
    i = 1
    
    if 'OGON_PIPE_PATH' not in os.environ:
        print("no pipe given in env")
        sys.exit(1)
        
    qtPath = os.environ['OGON_PIPE_PATH']
    
    print("fake QT: pipe={0}".format(qtPath))
    
    os.makedirs(os.path.dirname(qtPath), exist_ok=True)
    with open(qtPath, "w") as _f:
        pass
    
    time.sleep(60)
    