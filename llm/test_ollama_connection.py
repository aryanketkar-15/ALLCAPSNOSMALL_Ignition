import requests
import sys

def test_connection():
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "llama3:8b",
        "prompt": "Reply with exactly: OLLAMA_OK",
        "stream": False
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        reply = data.get("response", "")
        print(f"Response: {reply}")
        
        if "OLLAMA" in reply:
            print("CONNECTION OK")
        else:
            raise AssertionError(f"Expected 'OLLAMA' in response, got: {reply}")
            
    except requests.exceptions.RequestException as e:
        print(f"Connection failed: {e}")
        print("Please ensure 'ollama serve' is running.")
        sys.exit(1)

if __name__ == "__main__":
    test_connection()
