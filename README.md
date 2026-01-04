"""
TechCorp RAG Guardrails Demo
===========================

This project demonstrates how RAG (Retrieval-Augmented Generation) systems 
can leak sensitive information without proper guardrails.

Project Structure:
- src/: Source code files
- config/: Guardrails configuration 
- documents/: Test documents (PDF)
- tests/: Test data and sensitive data inventory

Usage:
- Run `python src/main.py` for RAG with guardrails
- Run `python src/simple_rag.py` for RAG without guardrails
- See `tests/SENSITIVE_DATA_INVENTORY.md` for test questions

Dependencies managed with UV package manager.
"""
