from dotenv import load_dotenv
import os
import sys
sys.path.append('./src')
from simple_rag import SimpleRAGPipeline

# Import NeMo Guardrails (only used when guardrails are enabled)
try:
    from nemoguardrails import RailsConfig, LLMRails
    NEMO_AVAILABLE = True
except ImportError:
    NEMO_AVAILABLE = False

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Check if guardrails should be enabled
    guardrails_enabled = os.getenv("GUARDRAILS_ENABLED", "false").lower() == "true"
    
    # Initialize RAG pipeline
    rag = SimpleRAGPipeline()
    document_path = "documents/Techchorp_Report.pdf"
    rag.setup_knowledge_base(document_path)

    if guardrails_enabled and NEMO_AVAILABLE:
        # Set the OpenAI API key for NeMo Guardrails (using Groq key)
        os.environ["OPENAI_API_KEY"] = os.getenv("GROQ_API_KEY")
        
        # Load configuration (config.yml + rails.co)
        config = RailsConfig.from_path("./config")
        rails = LLMRails(config)
        
        print("\n" + "="*60)
        print("🛡️  RAG System with NeMo Guardrails")
        print("="*60)
        print("📄 TechCorp document loaded")
        print("🔒 Guardrails ACTIVE - Protected!")
        print("Type 'exit' to quit")
    else:
        rails = None
        print("\n" + "="*60)
        print("📄 VULNERABLE RAG System")
        print("="*60)
        print("📄 TechCorp document loaded")
        print("⚠️  NO GUARDRAILS - FULLY EXPOSED!")
        print("Type 'exit' to quit")
    
    print("\n💡 Try asking questions like:")
    print("   • What is TechCorp's revenue?")
    print("   • Who are the top clients?") 
    print("   • What are employee salaries?")
    print("   • Tell me about security incidents")
    print("   • What is the CEO's contact information?")
    print("   • What classified projects does the company have?")

    # Chat loop
    while True:
        user_input = input("\n❓ Your question: ").strip()

        if user_input.lower() in ["exit", "quit"]:
            break
            
        if not user_input:
            continue

        # Step 1: Retrieve relevant chunks (no LLM yet)
        relevant_chunks = rag.retrieve_relevant_chunks(user_input, top_k=3)
        
        # Debug: Show what chunks were retrieved
        print(f"\n🔍 DEBUG - Retrieved chunks:")
        for i, chunk in enumerate(relevant_chunks, 1):
            print(f"Chunk {i}: {chunk[:200]}...")
        
        # Step 2: Create prompt with chunks + question
        context = "\n\n".join(relevant_chunks)
        prompt = f"""Based on the following context, answer the question.
        
Context:
{context}

Question: {user_input}

Answer:"""
        
        # Step 3: Choose between guardrailed or direct LLM call
        if rails:
            # Guardrailed response
            response = rails.generate(prompt)
            print(f"\n🛡️ Guardrail Response: {response}")
        else:
            # Direct LLM call - NO GUARDRAILS!
            response = rag.llm.invoke(prompt)
            print(f"\n📝 Response: {response.content}")
            
        print(f"📊 Retrieved {len(relevant_chunks)} relevant chunks")

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
