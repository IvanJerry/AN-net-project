import subprocess
import sys

METHODS = [
    "ShortTerm",
]

DATASETS = [0, 1, 2]
NOISE = "0.0"


def run(cmd: list):
    print("\n>>> Running:", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("Command failed:", " ".join(cmd))
        sys.exit(result.returncode)


def main():
    run([sys.executable, "data_extract.py"])
    run([sys.executable, "data_process.py"])

    for ds in DATASETS:
        for method in METHODS:
            run([
                sys.executable,
                "main.py",
                "--dataset", str(ds),
                "--method", method,
                "--noise", NOISE,
            ])


if __name__ == "__main__":
    main()
