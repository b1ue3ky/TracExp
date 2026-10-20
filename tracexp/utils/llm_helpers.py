import json
import os
from abc import ABC, abstractmethod

import httpx
import requests
import tiktoken
from openai import AzureOpenAI, OpenAI

from tracexp.utils.helpers import try_import_value

MODEL_NAMES = {
    # "deepseek-r1": "deepseek/deepseek-r1-0528:free",
    # "deepseek-r1": "deepseek/deepseek-r1-0528", # $0.20/$0.80/163,840
    "deepseek-r1": "deepseek/deepseek-chat-v3-0324", # $0.24/0.84/163,840
    "gpt-5": "openai/gpt-5", # $1.25/$10/400,000 => $0.625/5/M
    "gpt-oss-120b": "openai/gpt-oss-120b", # $0.072/$0.28/131,000
    "gpt-oss-20b": "openai/gpt-oss-20b", # $0/$0/131,072
    "claude-3-5-haiku": "anthropic/claude-3.5-haiku",# $0.80/$4/200,000
    "gemini-2.5-flash": "google/gemini-2.5-flash", # $0.30/$2.50/1,048,576
    "gemini-2.5-pro":"google/gemini-2.5-pro",# $1.25/$10/1,048,576
}

ADD_TYPE = {
    "deepseek-r1": False,
    "gpt-5": True,
    "gpt-oss-120b": False,
    "gpt-oss-20b": False,
    "claude-3-5-haiku": True,
    "gemini-2.5-flash": True,
    "gemini-2.5-pro": True,
}

def count_tokens(text, model="gpt-5"):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))

def response_detailed(llm_response, prompt, error=""):
    if type(llm_response) == dict: return llm_response
    response = {}
    if len(error) == 0:
        response["id"] = llm_response.id
        choices = {}
        for k,v in dict(llm_response.choices[0]).items():
            try:
                choices[k] = dict(v)
            except:
                choices[k] = v
        response["choices"] = [choices] 
        response["created"] = llm_response.created
        response["model"] = llm_response.model
        response["object"] = llm_response.object
        response["usage"] = dict(llm_response.usage)
        response['prompts'] = prompt
        response['status'] = '1'
    else:
        response['status'] = error

    return response
       
class LLM:
    def __init__(self, model="deepseek-r1", service="openrouter", openai=True, max_tries=5):
        assert service == "openrouter", "Only openrouter is supported for now"
        
        self.end_point = try_import_value('TRACEXP_LLM_ENDPOINT')
        self.api_key = try_import_value('TRACEXP_LLM_API_KEY')
        self.add_type = ADD_TYPE[model]
        self.model = MODEL_NAMES[model]
        self.openai = openai
        self.max_tries = max_tries

    def generate(self, prompt, conversation_history=None) -> str:
        """
        Generate a response from the model, given a prompt and previous conversation history.
        
        Args:
            prompt: The current user prompt or question.
            conversation_history: A list of previous messages in the conversation.
        
        Returns:
            str: Model's response based on the prompt and history.
        """
        
        if conversation_history is None:
            conversation_history = []
        
        # Add current prompt to the conversation history
        if type(prompt) == list:
            conversation_history.extend(prompt)
        else:
            conversation_history.append(prompt)
        
        if self.openai:
            client = OpenAI(
                base_url=self.end_point,
                api_key=self.api_key,
            )
            
            try:
                # Send the entire conversation history to the model
                response = client.chat.completions.create(
                    model=self.model,
                    messages=conversation_history,
                )
                response = response_detailed(response, prompt)
            except Exception as e:
                raise e
                return None, []
        else:
            payload = {"model": self.model, "messages": conversation_history}
            if "gpt-5" in self.model:
                payload['reasoning_effort'] = 'minimal' # https://platform.openai.com/docs/guides/latest-model#minimal-reasoning-effort
                payload['verbosity'] = 'low'

            response = None
            for _ in range(self.max_tries):
                try:
                    response = requests.post(
                        url=self.end_point,
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json",
                        },
                        data=json.dumps(
                            payload
                        )
                    )
                    response = response.json()
                except Exception as e:
                    continue
            if response is None or type(response) != dict:
                assert False, "network error"
                print(f"Error parsing response: {e}")
                return None, []
            
        assert response is not None and type(response) == dict, "Failed to get a response from the model after multiple attempts."
    
        if "choices" not in response:
            model_response = ""
        elif isinstance(response.get("choices"), list):        
            model_response = response.get("choices",[{}])[0].get("message",{}).get("content","")
        else:
            model_response = response.get("choices",{}).get("message",{}).get("content","")
                
        # Add model's response to the conversation history
        if self.add_type:
            conversation_history.append({"role": "assistant", "content": [{"type": "text", "text": model_response}]})
        else:
            conversation_history.append({"role": "assistant", "content": model_response})
        
        return response, conversation_history
    
def make_prompt(llm_client, prompt=None, sys_prompt=None, user_prompt=None, assist_prompt=None):
    if prompt is None:
        prompt = []
    
    if sys_prompt is not None:
        if not ADD_TYPE[llm_client]:
            prompt += [{"role": "system", "content": sys_prompt}]
        else:
            prompt += [{"role": "system", "content": [{"type":"text", "text": sys_prompt}]}]
    
    if user_prompt is not None:
        if not ADD_TYPE[llm_client]:
            prompt += [{"role": "user", "content": user_prompt}]
        else:
            prompt += [{"role": "user", "content": [{"type":"text", "text": user_prompt}]}]
        
    if assist_prompt is not None:
        if not ADD_TYPE[llm_client]:
            prompt += [{"role": "assistant", "content": assist_prompt}]
        else:
            prompt += [{"role": "assistant", "content": [{"type":"text", "text": assist_prompt}]}]        
        
    return prompt

def make_request(llm_client, prompt, conversation_history=None):
    llm = LLM(llm_client, openai=False)
    return llm.generate(prompt, conversation_history=conversation_history)