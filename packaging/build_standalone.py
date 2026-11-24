"""Native standalone build using the active locked release environment."""
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable,"-m","PyInstaller","--noconfirm","--onefile","--noupx",
    "--name","scriptsentinel","--paths",str(root/"src"),
    "--collect-all","tree_sitter_javascript","--collect-data","scriptsentinel",
    "--distpath",str(root/"dist"/"v1"),"--workpath",str(root/"build"/"standalone"),
    "--specpath",str(root/"build"),str(root/"packaging"/"standalone.py")],check=True)
