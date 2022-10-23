import uvicorn

from fastapi import FastAPI

from oauth2 import config_oauth
from config import SETTING
from routes import router

APP: FastAPI = FastAPI()

APP.include_router(router=router)
config_oauth(config=SETTING)


if __name__ == "__main__":
    uvicorn.run(APP, host="0.0.0.0", port=5000)
