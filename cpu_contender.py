import time 

while True: 
    start = time.time()
    for i in range(20000000): 
        pass
    elapsed_time = time.time() - start
    print(elapsed_time)
    time.sleep(max(1-elapsed_time, 0))
