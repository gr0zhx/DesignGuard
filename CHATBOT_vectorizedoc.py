import hashlib
import json
import os
from pathlib import Path
import pandas as pd
# Removed unused import: from langchain_unstructured import UnstructuredLoader
from langchain_core.documents import Document
from langchain_community.document_loaders import (
    UnstructuredFileLoader, CSVLoader, TextLoader,
    UnstructuredHTMLLoader, JSONLoader, UnstructuredXMLLoader,
    UnstructuredExcelLoader, UnstructuredMarkdownLoader, UnstructuredPDFLoader
)
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
PROCESSED_FILES = "processed_files.json"
VECTOR_DB_DIR = "vector_db"

def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

def load_processed_files():
    if os.path.exists(PROCESSED_FILES):
        with open(PROCESSED_FILES, "r") as f:
            return json.load(f)
    return {}

def save_processed_file(filename, file_hash):
    processed = load_processed_files()
    processed[filename] = file_hash
    with open(PROCESSED_FILES, "w") as f:
        json.dump(processed, f)

def custom_csv_loader(file_path):
    try:
        df = pd.read_csv(file_path, quotechar='"', encoding='utf-8', escapechar='\\', on_bad_lines='skip')
    except Exception:
        try:
            df = pd.read_csv(file_path, quotechar='"', encoding='utf-8', escapechar='\\', on_bad_lines='skip')
        except Exception as e:
            print(f"Error loading CSV {file_path}: {e}")
            return []

    documents = []
    for _, row in df.iterrows():
        text = "\n".join([f"{k}: {v}" for k, v in row.items() if pd.notna(v)])
        documents.append(Document(page_content=text, metadata={"source": str(file_path.name)}))
    return documents

def fix_metadata(documents):
    fixed_docs = []
    for doc in documents:
        # Buat salinan metadata
        clean_metadata = {}
        # Konversi semua nilai menjadi tipe primitif
        for key, value in doc.metadata.items():
            if isinstance(value, (list, tuple)):
                clean_metadata[key] = str(value)  # Konversi list/tuple ke string
            else:
                clean_metadata[key] = value
        
        # Buat dokumen baru dengan metadata yang sudah diperbaiki
        fixed_doc = Document(
            page_content=doc.page_content,
            metadata=clean_metadata
        )
        fixed_docs.append(fixed_doc)
    return fixed_docs

def process_documents():
    """
    Process documents for two focused databases:
    1. Security Requirements DB
    2. Threat & Vulnerability Patterns DB
    """
    
    # Updated data structure - more focused and realistic
    data_dirs = {
        "security_requirements": {
            "path": Path("data/security_requirements"),
            "description": "OWASP ASVS, Proactive Controls",
            "metadata_tags": "requirement,control,verification,design"  # Comma-separated string instead of list
        },
        "threat_patterns": {
            "path": Path("data/threat_patterns"), 
            "description": "CWE, CAPEC, KEV, MITRE ATT&CK subset",
            "metadata_tags": "threat,vulnerability,attack_pattern,weakness"  # Comma-separated string
        }
    }

    loaders = {
        ".pdf": lambda p: UnstructuredPDFLoader(str(p)).load(),
        ".csv": lambda p: custom_csv_loader(p),
        ".txt": lambda p: TextLoader(str(p)).load(),
        ".html": lambda p: UnstructuredHTMLLoader(str(p)).load(),
        ".xml": lambda p: UnstructuredXMLLoader(str(p)).load(),
        ".xlsx": lambda p: UnstructuredExcelLoader(str(p), mode="elements").load(),
        ".md": lambda p: UnstructuredMarkdownLoader(str(p)).load(),
        ".json": lambda p: JSONLoader(str(p), jq_schema=".[]", text_content=False).load()
    }

    for category, config in data_dirs.items():
        path_dir = config["path"]
        documents = []
        processed_files = load_processed_files()

        # Create directory if it doesn't exist
        path_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n🔍 Processing {category} database...")
        print(f"📁 Directory: {path_dir}")
        print(f"📋 Purpose: {config['description']}")

        for file_path in path_dir.glob("*.*"):
            ext = file_path.suffix.lower()
            if ext in loaders:
                file_hash = get_file_hash(file_path)
                file_name = f"{category}_{file_path.name}"

                if file_name in processed_files and processed_files[file_name] == file_hash:
                    print(f"[SKIP] {file_name} sudah diproses.")
                    continue

                try:
                    print(f"[LOAD] Memproses: {file_name}")
                    docs = loaders[ext](file_path)
                    
                    # Enhanced metadata for better retrieval - fixed to use string instead of list
                    for doc in docs:
                        doc.metadata.update({
                            "source": file_name,
                            "category": category,
                            "tags": config["metadata_tags"],  # Now a comma-separated string, not a list
                            "processed_date": "2025-01-21",
                            "db_type": category
                        })
                        
                    documents.extend(docs)
                    save_processed_file(file_name, file_hash)
                    
                except Exception as e:
                    print(f"[ERROR] Gagal memproses {file_name}: {str(e)}")

        if not documents:
            print(f"[INFO] Tidak ada dokumen baru untuk kategori {category}.")
            print(f"💡 Letakkan file sumber di: {path_dir}")
            continue

        # Enhanced text splitting for better semantic chunks
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1500,  # Smaller chunks for better precision
            chunk_overlap=200,
            length_function=len,
            add_start_index=True,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        text_chunks = text_splitter.split_documents(documents)

        # Create vector database
        db_path = os.path.join(VECTOR_DB_DIR, f"{category}_db")
        try:
            vectordb = Chroma.from_documents(
                documents=text_chunks,
                embedding=embeddings,
                persist_directory=db_path
            )
            
            
            print(f"[SUCCESS] ✅ {len(text_chunks)} chunks dari {len(documents)} dokumen")
            print(f"💾 Database disimpan di: {db_path}")
        except ValueError as e:
            print(f"[ERROR] Gagal menyimpan database {category}: {str(e)}")
            # Try with filtered metadata as a fallback
            try:
                print("[RETRY] Mencoba dengan metadata yang disederhanakan...")
                simple_chunks = fix_metadata(text_chunks)
                
                vectordb = Chroma.from_documents(
                    documents=simple_chunks,
                    embedding=embeddings,
                    persist_directory=db_path
                )
                
                print(f"[SUCCESS] ✅ {len(simple_chunks)} chunks dengan metadata sederhana")
            except Exception as e2:
                print(f"[FATAL ERROR] Tidak dapat menyimpan database {category}: {str(e2)}")

    print(f"\n🎉 Proses selesai! Database siap digunakan.")
    print(f"\n📊 Struktur Database:")
    print(f"🔒 Security Requirements DB → /vector_db/security_requirements_db")
    print(f"⚠️  Threat Patterns DB → /vector_db/threat_patterns_db")

if __name__ == "__main__":
    process_documents()