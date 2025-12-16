import uvicorn
import sys

from src.main import app

if __name__ == "__main__":
    reload = sys.argv[1] if len(sys.argv) > 1 else "False"

    if reload.lower() == "debug":
        uvicorn.run("src.__main__:app", host="0.0.0.0", port=8000, ws="none", reload=True, log_level="debug")
    else:
        uvicorn.run("src.__main__:app", host="0.0.0.0", port=8000, ws="none", reload=False, log_level="debug")
