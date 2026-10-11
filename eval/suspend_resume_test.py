import psutil
import sys
import time

def main():
    if len(sys.argv) < 2: return
    pid = int(sys.argv[1])
    try:
        p = psutil.Process(pid)
        
        # assert psutil status: stopped
        s = p.status()
        print(f"Status before 2nd suspend: {s}")
        if s != 'stopped':
            print("Assertion failed: process is not stopped!")
            
        p.suspend() # Second suspend!
        print(f"Status after 2nd suspend: {p.status()}")
        
        p.resume() # First resume!
        time.sleep(0.5)
        print(f"Status after 1st resume: {p.status()}")
        if p.status() != 'stopped':
            print("Assertion failed: process should still be stopped!")
            
        p.resume() # Second resume!
        time.sleep(0.5)
        print(f"Status after 2nd resume: {p.status()}")
        if p.status() != 'running':
            print("Assertion failed: process should be running!")
            
    except Exception as e:
        print(f"Error resuming {pid}: {e}")

if __name__ == "__main__":
    main()
