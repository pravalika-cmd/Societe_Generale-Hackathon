import os
import requests

def call_llm(prompt: str, system_prompt: str = "You are a professional Identity Security Analyst assistant.") -> str:
    """
    Abstractions for calling LLMs. Checks for environment variables:
    1. OPENAI_API_KEY -> Calls OpenAI Chat Completions API
    2. HF_API_KEY / HUGGINGFACE_API_KEY -> Calls Hugging Face Serverless Inference API
    
    If no keys are found, returns None, which flags the caller to fall back to Mock Mode.
    """
    openai_key = os.environ.get("OPENAI_API_KEY")
    hf_key = os.environ.get("HF_API_KEY") or os.environ.get("HUGGINGFACE_API_KEY")
    
    if openai_key:
        try:
            model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
            headers = {
                "Authorization": f"Bearer {openai_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2
            }
            # Timeout set to 15s to keep UI responsive
            resp = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Error contacting OpenAI API: {str(e)}. Falling back to offline context analyzer."
            
    elif hf_key:
        try:
            model = os.environ.get("HF_MODEL", "mistralai/Mistral-7B-Instruct-v0.2")
            headers = {
                "Authorization": f"Bearer {hf_key}",
                "Content-Type": "application/json"
            }
            # Construct a chat-like prompt structure for instruction-following models
            inputs = f"System: {system_prompt}\nUser: {prompt}\nAssistant:"
            payload = {
                "inputs": inputs,
                "parameters": {
                    "max_new_tokens": 512,
                    "temperature": 0.2
                }
            }
            url = f"https://api-inference.huggingface.co/models/{model}"
            resp = requests.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            
            result = resp.json()
            if isinstance(result, list) and len(result) > 0:
                text = result[0].get("generated_text", "")
                # Trim output if the prompt was echoed back
                if text.startswith(inputs):
                    text = text[len(inputs):].strip()
                return text
            elif isinstance(result, dict) and "generated_text" in result:
                return result["generated_text"]
            return str(result)
        except Exception as e:
            return f"Error contacting Hugging Face API: {str(e)}. Falling back to offline context analyzer."
            
    return None  # Triggers Mock Mode
