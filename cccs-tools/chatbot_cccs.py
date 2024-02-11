from dotenv import load_dotenv
import os
import requests
import json
import hashlib
import traceback 

from langchain.agents import initialize_agent, Tool
from langchain.agents import AgentType
from langchain_openai import OpenAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

load_dotenv('../.env')

AL_API_KEY = os.getenv('AL_API_KEY')
AL_SUBMIT_API_KEY = os.getenv('AL_SUBMIT_API_KEY')
AL_USER = os.getenv('AL_USER')
BEAVER_API_KEY = os.getenv('BEAVER_API_KEY')

from assemblyline_client import get_client
al_client = get_client("https://malware.cyber.gc.ca:443", apikey=(AL_USER, AL_API_KEY))
al_submit_client = get_client("https://malware.cyber.gc.ca:443", apikey=(AL_USER, AL_SUBMIT_API_KEY))

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
        return "AssemblyLine has not analyzed this file or there is no antivirus report available"

def get_antivirus_service_results_from_beaver(sha256):
    response = beaver_search(sha256)
    if response.status_code == 200:
        json_data = json.loads(response.text)
        if "SHADOW_SERVER" in json_data['malwareReport']['reports']:
            return json.dumps(json_data['malwareReport']['reports']['SHADOW_SERVER'][0]['results'])
    return "Beaver has not analyzed this file or there is no antivirus report available"

def calculateFileSha256(filename):
    with open(filename,"rb") as f:
        bytes = f.read() # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest();
        return readable_hash

def submitFileToAL(filename):
    from assemblyline_client import get_client
    al_submit_client = get_client("https://malware.cyber.gc.ca:443", apikey=(AL_USER, AL_SUBMIT_API_KEY))

    with open(filename,"rb") as f:
        bytes = f.read()
        submit_result = al_submit_client.submit(fname=filename, content=bytes)
    
    return submit_result
    
def chatbot():
    tools = [
        Tool(
            name = "GetAntivirusServiceResultsFromAssemblyLine",
            func=get_antivirus_service_results_from_al,
            description="useful for when you need to answer questions about AssemblyLine's antivirus reports for a given sha256.  AssemblyLine is a CCCS tool available at: https://malware.cyber.gc.ca"
        ),
        Tool(
            name = "GetAntivirusServiceResultsFromBeaver",
            func=get_antivirus_service_results_from_beaver,
            description="useful for when you need to answer questions about Beaver's antivirus reports for a given sha256.  Beaver is a CCCS tool available at https://beaver.ops.cyber.gc.ca"
        ),
        Tool(
            name = "CalculateFileSha256",
            func=calculateFileSha256,
            description="useful for when you need to calculate the sha256 of a file"
        ),
        Tool(
            name = "SubmitFileToAssemblyLine",
            func=submitFileToAL,
            description="useful for when you want to submit a file, using its filename, to the malware analysis platform AssemblyLine"
        )
    ]

    llm = ChatOpenAI(temperature=0.7, model="gpt-3.5-turbo-0125")
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", "You are very powerful assistant, but don't know current events.",),
            ("user", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ]
    )
    agent = create_openai_functions_agent(llm, tools, prompt)
    agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, debug=False)
    
    # Keep repeating the following
    while True:
        # Prompt user for input
        print()
        message = input("User: ")
        
        # Exit program if user inputs "quit"
        if message.lower() == "quit":
          break

        try:
            response = agent_executor.invoke({"input": message})['output']
        except:
            # printing stack trace 
            traceback.print_exc() 
        else:
            # Print the response 
            print(f"Bot: {response}")

if __name__ == "__main__":
    print("Start chatting with the bot (type 'quit' to stop)!")
    chatbot()