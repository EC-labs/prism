import subprocess
import sys
from pathlib import Path
import os
from src import main

def start():
    path = os.path.abspath(main.__file__)
    command = [
        "streamlit",
        "run",
        path,
    ]
    subprocess.run(
        command,
        check=True,
    )
