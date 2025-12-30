from nemoguardrails import RailsConfig, LLMRails
from dotenv import load_dotenv
import os

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Set the OpenAI API key for NeMo Guardrails (using Groq key)
    os.environ["OPENAI_API_KEY"] = os.getenv("GROQ_API_KEY")
    
    # Load configuration (config.yml + rails.co)
    config = RailsConfig.from_path("./config")

    # 2. Create NeMo Guardrails engine
    rails = LLMRails(config)

    print("NeMo Guardrails is running. Type 'exit' to quit.\n")

    # 3. Chat loop
    while True:
        user_input = input("User: ")

        if user_input.lower() in ["exit", "quit"]:
            break

        # 4. Generate response (guardrails + LLM)
        response = rails.generate(user_input)

        # 5. Return final guarded output
        print("Assistant:", response)
        print()

if __name__ == "__main__":
    main()
