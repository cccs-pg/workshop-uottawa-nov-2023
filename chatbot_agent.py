from dotenv import load_dotenv
import os
import requests
import json

from langchain.agents import initialize_agent, Tool
from langchain.agents import AgentType
from langchain.llms import OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.chat_models import ChatOpenAI

load_dotenv()

AL_API_KEY = os.getenv('AL_API_KEY')
AL_USER = os.getenv('AL_USER')
BEAVER_API_KEY = os.getenv('BEAVER_API_KEY')

from assemblyline_client import get_client
al_client = get_client("https://malware.cyber.gc.ca:443", apikey=(AL_USER, AL_API_KEY))

def beaver_search(sha256):
    response = requests.get(
        f"https://beaver.ops.cyber.gc.ca/auth/api/sha256/{sha256}/json",
        headers={
            "X-API-Key": BEAVER_API_KEY,
            "Accept": "application/json",
        }
    )
    return response

def get_antivirus_service_results_from_al(sha256):
    """Get the AssemblyLine antivirus report for the given sha256"""
    search_result = al_client.search.result(f'sha256:{sha256} AND response.service_name:AntiVirus', fl="*")
    # return "\n".join([i['title_text'] for i in search_result['items'][0]['result']['sections']])
    if len(search_result['items']) > 0:
        return json.dumps([i['title_text'] for i in search_result['items'][0]['result']['sections']])
    else:
        return "No antivirus report available for this sha256 in AssemblyLine"

def get_antivirus_service_results_from_beaver(sha256):
    response = beaver_search(sha256)
    if response.status_code == 200:
        json_data = json.loads(response.text)
        if "SHADOW_SERVER" in json_data['malwareReport']['reports']:
            return json.dumps(json_data['malwareReport']['reports']['SHADOW_SERVER'][0]['results'])
    return "No antivirus report available for this sha256 in Beaver"

def chatbot():
    llm = ChatOpenAI(temperature=0, model="gpt-3.5-turbo-1106")
    tools = [
        Tool(
            name = "GetAntivirusServiceResultsFromAssemblyLine",
            func=get_antivirus_service_results_from_al,
            description="useful for when you need to answer questions about AssemblyLine antivirus report for a given sha256"
        ),
        Tool(
            name = "GetAntivirusServiceResultsFromBeaver",
            func=get_antivirus_service_results_from_beaver,
            description="useful for when you need to answer questions about Beaver antivirus report for a given sha256"
        )
]
    mrkl = initialize_agent(tools, llm, agent=AgentType.OPENAI_FUNCTIONS, verbose=False, debug=False)
    
    # Create a list to store all the messages for context
    messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    ]
    
    # Keep repeating the following
    while True:
        # Prompt user for input
        print()
        message = input("User: ")
        
        # Exit program if user inputs "quit"
        if message.lower() == "quit":
          break
    
        response = mrkl.run(message)
        
        # Print the response 
        print(f"Bot: {response}")

if __name__ == "__main__":
  print("Start chatting with the bot (type 'quit' to stop)!")
  chatbot()