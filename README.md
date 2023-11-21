# workshop-uottawa-nov-2023
Repository of Jupyter notebooks prepared for the uOttawa workshop in November 2023

## Setup instructions for OpenAI
### Create an OpenAI account
* Visit https://openai.com/
* Click **Log in** 
* Choose **Sign up** and follow the instructions.

### Generate an OpenAI API key
* Go to https://platform.openai.com/api-keys and generate a new API key

### Create a .env file with your OpenAI API key
```
OPENAI_API_KEY=<enter your api key here>
```

## [Optional] Setup for CCCS tools (AssemblyLine and BeAVER)
### Request a My Cyber Portal account
* Go to [My Cyber Portal](https://portal-portail.cyber.gc.ca/en/)
* Click on **Sign in** (top right corner).
* Choose **Sign up now** and follow the instructions to request access to AssemblyLine and BeAVER.

### Generate API keys for both tools
Once you have received your Cyber Portal account, generate an API key in each tool. 

### Add your API keys to your .env file
```
AL_API_KEY=<enter your AssemblyLine api key here>
AL_USER=<enter your AssemblyLine user id>
BEAVER_API_KEY=<enter your BeAVER api key here>
```

## Create and activate a Python venv
To learn about venv, visit: https://docs.python.org/3/library/venv.html
```bash
python -m venv <path_to_new_virtual_environment>
source <path_to_new_virtual_environment>/bin/activate
```

## Install and start JupyterLab
JupyterLab is a web-based user interface to edit and execute Jupyter notebooks
```bash
pip install python-dotenv openai langchain assemblyline_client 
pip install jupyterlab
jupyter lab
```
