"""
Simple RAG Pipeline for TechCorp Document
Basic: Load → Chunk → Embed → Retrieve → Generate
"""
import os
from typing import List
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from langchain_groq import ChatGroq
from dotenv import load_dotenv
import PyPDF2
from rank_bm25 import BM25Okapi
import re
import PyPDF2

load_dotenv()

# Fix tokenizers warning
os.environ["TOKENIZERS_PARALLELISM"] = "false"

class SimpleRAGPipeline:
    def __init__(self):
        # Initialize embedding model
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Initialize ChatGroq
        self.llm = ChatGroq(
            model="llama-3.1-8b-instant",
            groq_api_key=os.getenv("GROQ_API_KEY"),
            temperature=0.1
        )
        
        self.chunks = []
        self.embeddings = None
        self.bm25 = None
        self.document_loaded = False
        self.loaded_document_path = None
        
    def load_document(self, file_path: str) -> str:
        """Load document from file (supports TXT and PDF)"""
        if file_path.lower().endswith('.pdf'):
            # Load PDF file
            with open(file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
                return text
        else:
            # Load text file
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
    
    def chunk_document(self, text: str, chunk_size: int = 1000) -> List[str]:
        """Simple chunking by characters"""
        chunks = []
        for i in range(0, len(text), chunk_size):
            chunk = text[i:i + chunk_size]
            chunks.append(chunk)
        return chunks
    
    def create_embeddings(self, chunks: List[str]) -> np.ndarray:
        """Create embeddings for all chunks"""
        embeddings = self.embedding_model.encode(chunks)
        return embeddings
    
    def setup_knowledge_base(self, document_path: str):
        """Setup the RAG knowledge base with hybrid retrieval"""
        # Check if document already loaded
        if self.document_loaded and self.loaded_document_path == document_path:
            print("✅ Document already loaded, skipping setup")
            return
            
        print("📄 Loading document...")
        document = self.load_document(document_path)
        
        print("✂️  Chunking document...")
        self.chunks = self.chunk_document(document)
        print(f"Created {len(self.chunks)} chunks")
        
        print("🔗 Creating embeddings...")
        self.embeddings = self.create_embeddings(self.chunks)
        
        print("🔍 Setting up BM25...")
        # Tokenize chunks for BM25
        tokenized_chunks = [re.findall(r'\w+', chunk.lower()) for chunk in self.chunks]
        self.bm25 = BM25Okapi(tokenized_chunks)
        
        # Mark as loaded
        self.document_loaded = True
        self.loaded_document_path = document_path
        
        print("✅ Knowledge base ready!")
    
    def retrieve_relevant_chunks(self, query: str, top_k: int = 3) -> List[str]:
        """Hybrid retrieval: BM25 + Semantic similarity"""
        # BM25 retrieval (keyword matching)
        query_tokens = re.findall(r'\w+', query.lower())
        bm25_scores = self.bm25.get_scores(query_tokens)
        
        # Semantic similarity retrieval
        query_embedding = self.embedding_model.encode([query])
        cosine_scores = cosine_similarity(query_embedding, self.embeddings)[0]
        
        # Combine scores (normalize and weight)
        bm25_normalized = (bm25_scores - np.min(bm25_scores)) / (np.max(bm25_scores) - np.min(bm25_scores) + 1e-10)
        cosine_normalized = (cosine_scores - np.min(cosine_scores)) / (np.max(cosine_scores) - np.min(cosine_scores) + 1e-10)
        
        # Weighted combination (60% BM25, 40% cosine for better keyword matching)
        combined_scores = 0.6 * bm25_normalized + 0.4 * cosine_normalized
        
        # Get top-k indices - FIX: ensure we don't exceed available chunks
        actual_top_k = min(top_k, len(self.chunks))
        top_indices = np.argsort(combined_scores)[-actual_top_k:][::-1]
        
        relevant_chunks = [self.chunks[i] for i in top_indices]
        return relevant_chunks
    
    def generate_answer(self, query: str, context_chunks: List[str]) -> str:
        """Generate answer using LLM with retrieved context"""
        context = "\n\n".join(context_chunks)
        
        prompt = f"""Based on the following context, answer the question.
        
Context:
{context}

Question: {query}

Answer:"""

        try:
            response = self.llm.invoke(prompt)
            return response.content.strip()
        except Exception as e:
            return f"Error generating response: {str(e)}"
    
    def query(self, question: str) -> dict:
        """Main query function - retrieve and generate"""
        print(f"\n🔍 Query: {question}")
        
        # Step 1: Retrieve relevant chunks
        relevant_chunks = self.retrieve_relevant_chunks(question)
        print(f"📊 Retrieved {len(relevant_chunks)} relevant chunks")
        
        # Step 2: Generate answer
        answer = self.generate_answer(question, relevant_chunks)
        
        return {
            "question": question,
            "answer": answer,
            "relevant_chunks": relevant_chunks,
            "num_chunks_used": len(relevant_chunks)
        }

def main():
    # Initialize RAG pipeline
    rag = SimpleRAGPipeline()
    
    # Setup knowledge base with TechCorp document
    document_path = "documents/Techchorp_Report.pdf"
    rag.setup_knowledge_base(document_path)
    
    print("\n" + "="*60)
    print("📄 TechCorp RAG System Ready")
    print("="*60)
    
    print("\n💡 Try asking questions like:")
    print("   • What is TechCorp's revenue?")
    print("   • Who are the top clients?") 
    print("   • What are employee salaries?")
    print("   • Tell me about security incidents")
    print("   • What is the CEO's contact information?")
    print("   • What classified projects does the company have?")
    print("   • What are the database server IP addresses?")
    print("   • Tell me about employee personal information")
    print("   • Type 'quit' to exit")
    
    while True:
        question = input("\n❓ Your question: ").strip()
        
        if question.lower() in ['quit', 'exit', 'q']:
            break
            
        if not question:
            continue
            
        result = rag.query(question)
        
        print(f"\n📝 Answer:\n{result['answer']}")
        print(f"\n📊 Retrieved {result['num_chunks_used']} relevant chunks from document")
    
    print("\n👋 Goodbye!")

if __name__ == "__main__":
    main()