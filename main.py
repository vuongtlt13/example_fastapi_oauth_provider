import uvicorn

from fastapi import FastAPI

from oauth2 import config_oauth
from config import SETTING

APP: FastAPI = FastAPI()

config_oauth(config=SETTING)

if __name__ == "__main__":
    uvicorn.run(APP, host="0.0.0.0", port=8000)
