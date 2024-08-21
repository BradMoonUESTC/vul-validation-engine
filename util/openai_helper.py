import requests
import json

class OpenAIHelper:
    def __init__(self, api_key, api_base="api.openai.com"):
        self.api_key = api_key
        self.api_base = api_base

    def ask_openai_common(self, prompt):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        data = {
            "model": "gpt-4-turbo",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        response = requests.post(f'https://{self.api_base}/v1/chat/completions', headers=headers, json=data)
        try:
            response_json = response.json()
        except Exception as e:
            return ''
        if 'choices' not in response_json:
            return ''
        return response_json['choices'][0]['message']['content']

    def ask_openai_for_json(self, prompt):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        data = {
            "model": "gpt-4-turbo",
            "response_format": { "type": "json_object" },
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant designed to output JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        response = requests.post(f'https://{self.api_base}/v1/chat/completions', headers=headers, json=data)
        try:
            response_json = response.json()
        except json.JSONDecodeError:
            return ''
        
        if 'choices' not in response_json:
            return ''
        
        return response_json['choices'][0]['message']['content']
