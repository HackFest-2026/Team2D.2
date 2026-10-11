import os
import time

sandbox = os.path.abspath("../../sandbox")
os.makedirs(sandbox, exist_ok=True)

print(f"Benign writer started in {sandbox}")
while True:
    try:
        path = os.path.join(sandbox, f"benign_{time.time()}.txt")
        with open(path, "w") as f:
            for _ in range(100):
                f.write("This is a benign log line. " * 10 + "\n")
        time.sleep(0.5)
    except KeyboardInterrupt:
        break
