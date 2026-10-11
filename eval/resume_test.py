import psutil
import sys

def main():
    if len(sys.argv) < 2: return
    pid = int(sys.argv[1])
    try:
        p = psutil.Process(pid)
        p.resume()
        print(f"Resumed PID {pid} successfully")
    except Exception as e:
        print(f"Error resuming {pid}: {e}")

if __name__ == "__main__":
    main()
