import os
import json
import streamlit as st
import requests
from datetime import datetime
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_groq import ChatGroq
from langchain.memory import ConversationBufferMemory
from langchain.chains import ConversationalRetrievalChain
from langchain.prompts import PromptTemplate

# Multi-provider imports
try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    import ollama
except ImportError:
    ollama = None

try:
    from groq import Groq
except ImportError:
    Groq = None

# ---------------------------
# Konfigurasi & API key - Updated for multiple providers
# ---------------------------
working_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(working_dir, "config.json")

try:
    with open(config_path, "r") as config_file:
        config_data = json.load(config_file)
except Exception as e:
    st.error(f"Gagal memuat config.json: {e}")
    st.stop()

# ---------------------------
# Enhanced Security Analysis Prompt - Improved with more explicit guidance and examples
# ---------------------------
SECURITY_ANALYSIS_PROMPT = """
Berdasarkan DOKUMEN KONTEKS berikut:
---
{context}
---

Sebagai ahli keamanan SSDLC, analisis profil fitur berikut dan berikan rekomendasi terstruktur:

PROFIL FITUR:
{question}

INSTRUKSI PENTING:
- WAJIB menggunakan MINIMAL 3 referensi CWE (format: "CWE-79", "CWE-89", "CWE-287")
- WAJIB menggunakan MINIMAL 3 referensi CAPEC (format: "CAPEC-66", "CAPEC-67", "CAPEC-114")
- WAJIB menggunakan MINIMAL 5 referensi ASVS (format: "ASVS-V2.1.1", "ASVS-V4.1.3")
- JANGAN PERNAH menggunakan placeholder seperti "CWE-XXX" - HARUS menggunakan nomor yang sebenarnya
- SELALU cantumkan nomor referensi di awal setiap item dan jelaskan secara detail
- JANGAN LEWATKAN salah satu bagian berikut: REQUIREMENTS CHECKLIST, THREAT SCENARIOS, SECURITY CONTROLS

BERIKAN ANALISIS DALAM FORMAT YANG SUDAH DITENTUKAN BERIKUT:

## 🔒 SECURITY REQUIREMENTS CHECKLIST
Berdasarkan OWASP ASVS dan Proactive Controls, identifikasi MINIMAL 5 persyaratan keamanan yang paling relevan:
- [ ] **ASVS-V2.1.1 - [Kategori]**: [Requirement spesifik dengan detail yang komprehensif]
- [ ] **ASVS-V4.1.3 - [Kategori]**: [Requirement spesifik dengan detail yang komprehensif]
- [ ] **ASVS-V5.2.1 - [Kategori]**: [Requirement spesifik dengan detail yang komprehensif]
- [ ] **ASVS-V7.1.2 - [Kategori]**: [Requirement spesifik dengan detail yang komprehensif]
- [ ] **ASVS-V14.2.1 - [Kategori]**: [Requirement spesifik dengan detail yang komprehensif]

## ⚠️ THREAT SCENARIOS & ATTACK VECTORS
Berdasarkan CWE, CAPEC, dan OWASP Top 10, identifikasi MINIMAL 3 skenario ancaman yang BERBEDA dan spesifik:

### Threat 1: CWE-79 - Cross-Site Scripting (XSS)
- **Attack Vector**: CAPEC-63 - [Langkah-langkah serangan yang spesifik dan detail]
- **Impact**: [High/Medium/Low] - [Deskripsi dampak teknis yang spesifik]
- **Likelihood**: [High/Medium/Low] - [Alasan berdasarkan konteks sistem]
- **Affected Component**: [Komponen fitur yang spesifik]

### Threat 2: CWE-89 - SQL Injection
- **Attack Vector**: CAPEC-66 - [Langkah-langkah serangan yang BERBEDA dari Threat 1]
- **Impact**: [High/Medium/Low] - [Dampak yang BERBEDA dari Threat 1]
- **Likelihood**: [High/Medium/Low] - [Alasan yang spesifik]
- **Affected Component**: [Komponen yang mungkin berbeda]

### Threat 3: CWE-287 - Improper Authentication
- **Attack Vector**: CAPEC-114 - [Serangan yang fokus pada aspek keamanan yang BERBEDA]
- **Impact**: [High/Medium/Low] - [Dampak yang unik]
- **Likelihood**: [High/Medium/Low] - [Justifikasi yang berbeda]
- **Affected Component**: [Komponen spesifik]

## 🛡️ SECURITY CONTROLS & COUNTERMEASURES
Berdasarkan NIST CSF dan OWASP Defense in Depth:

### Technical Controls
1. **CWE-79/ASVS-V5.2.2 - [Nama Control spesifik]**: [Implementasi teknis yang detail dengan referensi ke teknologi/framework spesifik]
2. **CWE-89/ASVS-V5.3.4 - [Nama Control kedua]**: [Implementasi yang berbeda dengan teknologi berbeda]
3. **CWE-287/ASVS-V2.2.1 - [Nama Control ketiga]**: [Solusi yang fokus pada mitigasi CWE/CAPEC yang disebutkan di atas]

### Administrative Controls
1. **ASVS-V14.1.1 - [Policy/Procedure]**: [Detail implementasi dengan referensi standar]
2. **ASVS-V13.2.3 - [Training/Awareness]**: [Program spesifik untuk mencegah ancaman yang diidentifikasi]

## 🎯 IMPLEMENTATION CHECKLIST
- [ ] **Pre-Development**: [Aktivitas sebelum coding dengan tools spesifik]
- [ ] **During Development**: [Praktik coding secure dengan framework/library spesifik]
- [ ] **Testing Phase**: [Jenis testing keamanan spesifik dengan tools]
- [ ] **Deployment**: [Konfigurasi keamanan infrastruktur]
- [ ] **Maintenance**: [Monitoring dan update rutin]

## 🎯 RISK ASSESSMENT SUMMARY
- **Critical Risk**: [Ancaman dengan dampak tertinggi] (CWE-xxx)
- **Recommended Priority**: [Urutan penanganan berdasarkan risk/effort matrix]
- **Quick Wins**: [Kontrol yang mudah diimplementasi dengan dampak signifikan]

CATATAN: SEMUA referensi CWE, CAPEC, dan ASVS HARUS menggunakan nomor yang sebenarnya, bukan placeholder. Pastikan SETIAP ancaman memiliki referensi CWE dan CAPEC yang tepat.
"""

# ---------------------------
# Setup Vector Stores
# ---------------------------
@st.cache_resource
def setup_vectorstores():
    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )
    
    vectorstores = {}
    
    # Database 1: Security Requirements
    req_db_path = os.path.join(working_dir, "vector_db/security_requirements_db")
    if os.path.exists(req_db_path):
        vectorstores["security_requirements"] = Chroma(
            persist_directory=req_db_path,
            embedding_function=embeddings
        )
    else:
        st.warning("Security Requirements database tidak ditemukan.")
    
    # Database 2: Threat Patterns
    threat_db_path = os.path.join(working_dir, "vector_db/threat_patterns_db")
    if os.path.exists(threat_db_path):
        vectorstores["threat_patterns"] = Chroma(
            persist_directory=threat_db_path,
            embedding_function=embeddings
        )
    else:
        st.warning("Threat Patterns database tidak ditemukan.")
    
    return vectorstores

# ---------------------------
# Enhanced retrieval with multiple strategies - Optimized to prioritize standards references
# ---------------------------
def enhanced_retrieval_multi_strategy(query, vectorstores, k_per_db=7):
    """
    Enhanced retrieval using multiple search strategies to get CWE/CAPEC/ASVS data
    """
    all_docs = []
    
    # Generate more targeted search queries based on the input
    enhanced_queries = [query]  # Original query
    
    # Add CWE-specific queries with common vulnerability types
    enhanced_queries.extend([
        f"{query} CWE weakness vulnerability",
        f"common weakness enumeration {query}",
        "CWE-79 XSS cross site scripting",
        "CWE-89 SQL injection",
        "CWE-287 authentication bypass",
        "CWE-306 missing authentication",
        "CWE-434 unrestricted file upload",
        "CWE-22 path traversal",
        "CWE-94 code injection",
        "CWE-863 incorrect authorization",
        "CWE-352 cross site request forgery"
    ])
    
    # Add CAPEC-specific queries with expanded patterns  
    enhanced_queries.extend([
        f"{query} CAPEC attack pattern",
        f"attack mechanism {query}",
        "CAPEC-66 SQL injection",
        "CAPEC-63 Cross-Site Scripting",
        "CAPEC-67 String SQL injection",
        "CAPEC-114 authentication abuse",
        "CAPEC-242 code injection",
        "CAPEC-126 path traversal",
        "CAPEC-31 Cross-Site Request Forgery",
        "CAPEC-593 Session Hijacking"
    ])
    
    # Add ASVS-specific queries with version numbers
    enhanced_queries.extend([
        f"{query} ASVS application security verification",
        f"OWASP ASVS {query}",
        "ASVS-V1 architecture verification",
        "ASVS-V2.1 authentication verification", 
        "ASVS-V4.1 access control verification",
        "ASVS-V5.2 validation verification",
        "ASVS-V6.1 cryptography verification",
        "ASVS-V7.1 error handling",
        "ASVS-V11.1 business logic verification",
        "ASVS-V14.1 configuration verification"
    ])
    
    if "security_requirements" in vectorstores:
        # Search security requirements with enhanced queries
        for search_query in enhanced_queries[:12]:  # Increased limit for better coverage
            req_docs = vectorstores["security_requirements"].as_retriever(
                search_kwargs={"k": 3}
            ).get_relevant_documents(search_query)
            all_docs.extend(req_docs)
    
    if "threat_patterns" in vectorstores:
        # Search threat patterns with enhanced queries
        for search_query in enhanced_queries:
            threat_docs = vectorstores["threat_patterns"].as_retriever(
                search_kwargs={"k": 3}
            ).get_relevant_documents(search_query)
            all_docs.extend(threat_docs)
    
    # Remove duplicates based on content
    unique_docs = []
    seen_content = set()
    for doc in all_docs:
        content_hash = hash(doc.page_content[:100])  # Use first 100 chars as identifier
        if content_hash not in seen_content:
            seen_content.add(content_hash)
            unique_docs.append(doc)
    
    # Priority ranking: prioritize documents with CWE, CAPEC, or ASVS references
    priority_docs = []
    secondary_docs = []
    regular_docs = []
    
    # Keywords to boost document priority
    high_priority_patterns = ['CWE-', 'CAPEC-', 'ASVS-V']
    secondary_patterns = ['weakness', 'vulnerability', 'attack pattern', 'security verification']
    
    for doc in unique_docs:
        content = doc.page_content.upper()
        if any(pattern in content for pattern in high_priority_patterns):
            priority_docs.append(doc)
        elif any(pattern.upper() in content for pattern in secondary_patterns):
            secondary_docs.append(doc)
        else:
            regular_docs.append(doc)
    
    # Return priority docs first, then secondary docs, then regular docs
    result_docs = priority_docs + secondary_docs + regular_docs
    return result_docs[:25]  # Increased limit for better coverage

# ---------------------------
# Enhanced narrative query format
# ---------------------------
def format_profile_for_retrieval(profile):
    """Enhanced narrative format that helps retrieve CWE/CAPEC data"""
    
    # Build risk-focused narrative
    narrative_parts = []
    
    # System type with security implications
    system_type = profile.get('system_type', 'aplikasi')
    narrative_parts.append(f"Analisis keamanan {system_type}")
    
    # Authentication vulnerabilities
    if profile.get('auth_features'):
        auth_features = profile.get('auth_features', [])
        narrative_parts.append("autentikasi")
        
        if "Multi-Factor Authentication (MFA)" in auth_features:
            narrative_parts.extend(["MFA", "multi-factor", "CWE-287", "authentication bypass", "CAPEC-114"])
        if "Social Login (OAuth)" in auth_features:
            narrative_parts.extend(["OAuth", "federation", "CWE-346", "identity provider", "CAPEC-273"])
        if "Username/Password Login" in auth_features:
            narrative_parts.extend(["password", "brute force", "CWE-307", "credential stuffing", "CAPEC-16"])
    
    # Data processing vulnerabilities
    if profile.get('data_features'):
        data_features = profile.get('data_features', [])
        
        if "User Form Input" in data_features:
            narrative_parts.extend(["input validation", "CWE-79", "XSS", "CAPEC-63", "CWE-89", "SQL injection", "CAPEC-66"])
        if "File Upload" in data_features:
            narrative_parts.extend(["file upload", "CWE-434", "unrestricted upload", "CAPEC-1", "CWE-22", "path traversal"])
        if "Search Functionality" in data_features:
            narrative_parts.extend(["search", "injection", "CWE-89", "LDAP injection", "CAPEC-136"])
    
    # File types specific risks
    if profile.get('upload_types'):
        file_types = profile.get('upload_types', [])
        for file_type in file_types:
            if 'archive' in file_type.lower() or 'zip' in file_type.lower():
                narrative_parts.extend(["archive", "zip slip", "CWE-22", "path traversal", "CAPEC-126"])
            if 'code' in file_type.lower():
                narrative_parts.extend(["code execution", "CWE-94", "remote code execution", "CAPEC-242"])
    
    # Integration risks
    if profile.get('integration_features'):
        integrations = profile.get('integration_features', [])
        for integration in integrations:
            if 'payment' in integration.lower():
                narrative_parts.extend(["payment", "PCI", "financial", "CWE-311", "CAPEC-31", "CSRF"])
            if 'third-party' in integration.lower():
                narrative_parts.extend(["third party", "supply chain", "CWE-1357", "CAPEC-437"])
    
    # Add ASVS references based on features
    narrative_parts.extend([
        "ASVS-V1.1 architecture", "ASVS-V2.1 authentication", 
        "ASVS-V4.1 access control", "ASVS-V5.2 input validation",
        "ASVS-V7.1 error handling", "ASVS-V14.1 configuration"
    ])
    
    # Create comprehensive search query
    search_query = " ".join(narrative_parts)
    
    return search_query

# ---------------------------
# Chain LLM + Retriever - Updated for multiple providers with optimized settings
# ---------------------------
def create_analysis_chain(provider_choice="groq", model_choice="llama-3.1-8b-instant", ollama_url="http://localhost:11434"):
    """Create LLM chain based on selected provider"""
    global config_data
    
    if provider_choice == "ollama":
        # Use Ollama via requests with optimized settings
        class OllamaLLM:
            def __init__(self, base_url, model):
                self.base_url = base_url
                self.model = model
            
            def invoke(self, prompt):
                try:
                    payload = {
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.1,
                            "top_p": 0.95,
                            "top_k": 40,
                            "num_predict": 2048,
                            "stop": ["User:", "Human:", "<|im_end|>"]
                        }
                    }
                    
                    response = requests.post(
                        f"{self.base_url}/api/generate",
                        json=payload,
                        timeout=90
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        # Create a response object similar to LangChain
                        class Response:
                            def __init__(self, content):
                                self.content = content
                        return Response(result.get('response', ''))
                    else:
                        st.error(f"Ollama error: {response.status_code}")
                        return Response("Error generating response")
                        
                except Exception as e:
                    st.error(f"Ollama request failed: {e}")
                    return Response("Error generating response")
        
        llm = OllamaLLM(ollama_url, model_choice)
        
    elif provider_choice == "gemini":
        # Use Google Gemini API
        if genai is None:
            st.error("❌ Google Generative AI library not installed. Please run: pip install google-generativeai")
            st.stop()
        
        api_key = config_data.get("GEMINI_API_KEY")
        if not api_key:
            st.error("❌ GEMINI_API_KEY not found in config.json!")
            st.stop()
        
        genai.configure(api_key=api_key)
        
        class GeminiLLM:
            def __init__(self, model_name):
                self.model = genai.GenerativeModel(model_name)
            
            def invoke(self, prompt):
                try:
                    response = self.model.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.1,
                            top_p=0.9,
                            top_k=40,
                            max_output_tokens=2048,
                            stop_sequences=None
                        )
                    )
                    
                    class Response:
                        def __init__(self, content):
                            self.content = content
                    return Response(response.text)
                    
                except Exception as e:
                    st.error(f"Gemini request failed: {e}")
                    class Response:
                        def __init__(self, content):
                            self.content = content
                    return Response("Error generating response")
        
        llm = GeminiLLM(model_choice)
        
    elif provider_choice == "groq":
        # Use Groq API
        api_key = config_data.get("GROQ_API_KEY")
        if not api_key:
            st.error("❌ GROQ_API_KEY not found in config.json!")
            st.stop()
        
        os.environ["GROQ_API_KEY"] = api_key
        
        from langchain_groq import ChatGroq
        llm = ChatGroq(
            model=model_choice, 
            temperature=0.1,
            max_tokens=2048
        )
    else:
        st.error(f"Unsupported provider: {provider_choice}")
        st.stop()
    
    prompt = PromptTemplate(
        template=SECURITY_ANALYSIS_PROMPT, 
        input_variables=["context", "question"]
    )
    return llm, prompt

# ---------------------------
# Feature Profile Generation
# ---------------------------
def generate_feature_profile():
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    feature_profile = {
        "timestamp": current_time, 
        "user": "gr0zhx"
    }
    
    st.markdown("### 🎯 System Context")
    col1, col2 = st.columns(2)
    
    with col1:
        feature_profile["system_type"] = st.selectbox(
            "Tipe Aplikasi:",
            ["Web Application", "Mobile App (Android/iOS)", "Desktop Application", 
             "API/Microservice", "Embedded/IoT System"]
        )
        
        feature_profile["business_criticality"] = st.selectbox(
            "Tingkat Kritikalitas Bisnis:",
            ["Low (Internal tools)", "Medium (Customer-facing)", 
             "High (Revenue-critical)", "Critical (Business-essential)"]
        )
    
    with col2:
        feature_profile["deployment"] = st.selectbox(
            "Environment Deployment:",
            ["Cloud (AWS/Azure/GCP)", "On-premises", "Hybrid", "Mobile App Store"]
        )
        
        feature_profile["user_base"] = st.selectbox(
            "Expected User Base:",
            ["<100 internal", "100-1K internal", "1K-10K external", 
             "10K-100K external", ">100K public"]
        )

    st.markdown("### 🔧 Core Functionality")
    
    # Authentication Features
    with st.expander("🔐 Authentication & Identity Management", expanded=True):
        feature_profile["auth_features"] = st.multiselect(
            "Select applicable authentication features:",
            ["Username/Password Login", "Multi-Factor Authentication (MFA)", 
             "Social Login (OAuth)", "Single Sign-On (SSO)", 
             "Password Reset/Recovery", "Account Registration",
             "Session Management", "Remember Me functionality"]
        )

    # Data Processing Features  
    with st.expander("📊 Data Processing & Input", expanded=True):
        feature_profile["data_features"] = st.multiselect(
            "Select data processing features:",
            ["User Form Input", "File Upload", "Data Import/Export", 
             "Search Functionality", "Real-time Data Processing",
             "Batch Data Processing", "Data Validation", "Content Generation"]
        )
        
        if "File Upload" in feature_profile["data_features"]:
            feature_profile["upload_types"] = st.multiselect(
                "File types allowed:",
                ["Images (JPG, PNG, GIF)", "Documents (PDF, DOC, TXT)", 
                 "Spreadsheets (XLS, CSV)", "Archives (ZIP, RAR)",
                 "Media Files (MP3, MP4)", "Code Files", "Any File Type"]
            )

    # API & Integration
    with st.expander("🔗 External Integration", expanded=True):
        feature_profile["integration_features"] = st.multiselect(
            "External integrations:",
            ["Third-party APIs", "Payment Processing", "Email/SMS Services",
             "Database Integration", "Cloud Storage", "Analytics Services",
             "Social Media APIs", "Webhook Endpoints"]
        )

    st.markdown("### 🛡️ Security Context")
    col1, col2 = st.columns(2)
    
    with col1:
        feature_profile["data_sensitivity"] = st.selectbox(
            "Data Sensitivity Level:",
            ["Public", "Internal", "Confidential", "Restricted"]
        )
        
        feature_profile["compliance"] = st.multiselect(
            "Compliance Requirements:",
            ["GDPR", "PCI-DSS", "HIPAA", "SOX", "ISO 27001", "None"]
        )
    
    with col2:
        feature_profile["existing_controls"] = st.multiselect(
            "Existing Security Controls:",
            ["Input Validation", "Output Encoding", "Authentication", 
             "Authorization", "Encryption", "Logging & Monitoring",
             "Rate Limiting", "None Implemented Yet"]
        )

    # Enhanced security context with explicit reference prompts
    st.markdown("### 📋 Security References")
    help_text = "Add specific CWE, CAPEC, and ASVS references for better results"
    
    feature_profile["additional_context"] = st.text_area(
        "Additional Context and References:",
        placeholder="Describe specific security concerns including CWE, CAPEC, and ASVS references. Example: Must address CWE-79 (XSS), CWE-89 (SQL injection), ASVS-V5.3 (Output Encoding), etc.",
        help=help_text
    )

    return feature_profile

# ---------------------------
# Streamlit UI
# ---------------------------
st.set_page_config(
    page_title="DesignGuard - SSDLC Security Assistant", 
    layout="wide", 
    page_icon="🛡️"
)

st.title("🛡️ DesignGuard: Focused SSDLC Security Analysis")
st.markdown("*Feature-based security requirements & threat modeling for design phase*")

# Display current user and datetime in header
current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
st.info(f"Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): {current_time}")
st.info(f"Current User's Login: gr0zhx")

# Show provider status if analysis has been done
if "analysis_result" in st.session_state and st.session_state.analysis_result:
    provider_info = st.session_state.analysis_result.get('provider_used', 'Unknown')
    st.success(f"🤖 Last Analysis Generated by: {provider_info}")

# Enhanced Sidebar
with st.sidebar:
    st.header("🤖 LLM Provider Configuration")
    
    # Provider Selection
    provider_choice = st.selectbox(
        "Choose LLM Provider:",
        ["groq", "gemini", "ollama"],
        index=0,
        help="Select which LLM provider to use for analysis"
    )
    
    # Provider-specific configurations
    ollama_url = None  # Initialize for all providers
    
    if provider_choice == "gemini":
        st.info("🧠 Using Google Gemini (Cloud API)")
        model_choice = st.selectbox(
            "Gemini Model:",
            ["gemini-1.5-flash", "gemma-3-27b-it", "gemma-3-12b-it"],
            help="Select Gemini/Gemma model variant"
        )
        
    elif provider_choice == "ollama":
        st.info("🦙 Using Ollama (Local)")
        model_choice = st.selectbox(
            "Ollama Model:",
            ["llama3.2:3b", "llama3.2:1b", "llama3.1:8b", "qwen2.5:0.5b", "gemma2:2b"],
            help="Select Ollama model variant"
        )
        ollama_url = st.text_input("Ollama Base URL:", value="http://localhost:11434")
        
    elif provider_choice == "groq":
        st.info("⚡ Using Groq (Cloud API)")
        model_choice = st.selectbox(
            "Groq Model:",
            ["llama-3.1-8b-instant", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"],
            help="Select Groq model variant"
        )
    
    # Show API key status based on provider
    try:
        if provider_choice == "gemini":
            if config_data.get("GEMINI_API_KEY"):
                st.success("✅ Gemini API key found")
            else:
                st.error("❌ Gemini API key not found")
        elif provider_choice == "groq":
            if config_data.get("GROQ_API_KEY"):
                st.success("✅ Groq API key found")
            else:
                st.error("❌ Groq API key not found")
        elif provider_choice == "ollama":
            st.info("🔧 Using local Ollama (no API key needed)")
            # Test Ollama connection
            try:
                response = requests.get(f"{ollama_url}/api/tags", timeout=5)
                if response.status_code == 200:
                    st.success("✅ Ollama server connected")
                else:
                    st.error("❌ Ollama server not responding")
            except:
                st.warning("⚠️ Cannot connect to Ollama server")
                
    except:
        st.error("❌ Config file not found")
    
    st.divider()
    st.header("📚 Knowledge Base")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Update DB"):
            from CHATBOT_vectorizedoc import process_documents
            with st.spinner("Processing..."):
                process_documents()
            st.success("Updated!")
    
    with col2:
        if st.button("🧹 Reset"):
            st.session_state.clear()
            st.experimental_rerun()
    
    st.markdown("### 📊 Database Structure")
    st.info("""
    **🔒 Security Requirements DB**
    - OWASP ASVS (V2,V4,V5,V7)
    - OWASP Proactive Controls
    - NIST SSDF (Design phase)
    
    **⚠️ Threat Patterns DB**
    - CWE Top 25 (cwec_v4.17.xml)
    - CAPEC Attack Patterns (capec_v3.9.xml)
    - OWASP Top 10 (2021)
    - MITRE ATT&CK (subset)
    """)
    
    # Enhanced stats display
    st.markdown("### 📈 Analysis Stats")
    if "analysis_result" in st.session_state and st.session_state.analysis_result:
        docs_count = len(st.session_state.analysis_result.get("docs", []))
        st.metric("Documents Retrieved", docs_count)
        
        req_docs = len([d for d in st.session_state.analysis_result.get("docs", []) 
                       if d.metadata.get("category") == "security_requirements"])
        threat_docs = len([d for d in st.session_state.analysis_result.get("docs", []) 
                          if d.metadata.get("category") == "threat_patterns"])
        
        st.metric("Requirements Sources", req_docs)
        st.metric("Threat Sources", threat_docs)
        
        # Add reference counts
        response = st.session_state.analysis_result.get("response", "")
        import re
        cwe_count = len(re.findall(r'CWE-\d+', response))
        capec_count = len(re.findall(r'CAPEC-\d+', response))
        asvs_count = len(re.findall(r'ASVS-V\d+(\.\d+)?(\.\d+)?', response))
        
        st.metric("CWE References", cwe_count, help="Number of CWE references in response")
        st.metric("CAPEC References", capec_count, help="Number of CAPEC references in response")
        st.metric("ASVS References", asvs_count, help="Number of ASVS references in response")
    
    # Reference guides
    st.markdown("### 🧠 Reference Examples")
    with st.expander("Common CWE References"):
        st.code("""
CWE-79: Cross-Site Scripting (XSS)
CWE-89: SQL Injection
CWE-287: Improper Authentication
CWE-434: Unrestricted File Upload
CWE-22: Path Traversal
CWE-352: CSRF
CWE-306: Missing Authentication
        """)
    
    with st.expander("Common CAPEC References"):
        st.code("""
CAPEC-66: SQL Injection
CAPEC-63: Cross-Site Scripting
CAPEC-114: Authentication Abuse
CAPEC-126: Path Traversal
CAPEC-242: Code Injection
CAPEC-593: Session Hijacking
        """)
    
    with st.expander("Common ASVS References"):
        st.code("""
ASVS-V1.1.1: App Security Architecture
ASVS-V2.1.1: Authentication Controls
ASVS-V4.1.1: Access Controls
ASVS-V5.2.1: Input Validation
ASVS-V7.1.1: Error Handling
ASVS-V14.1.1: Configuration
        """)

# Setup
if "vectorstores" not in st.session_state:
    st.session_state.vectorstores = setup_vectorstores()

# Main Interface
with st.form("security_analysis_form"):
    st.markdown("## 📝 Feature Security Profiler")
    
    feature_profile = generate_feature_profile()
    
    # Performance optimization notice
    st.info("⚡ For better performance, include specific references in Additional Context (CWE-xx, CAPEC-xx, ASVS-Vx.x.x)")
    
    submitted = st.form_submit_button("🔍 Generate Security Analysis", use_container_width=True)
    
    if submitted:
        if not st.session_state.vectorstores:
            st.error("No databases available. Please process documents first.")
        else:
            with st.spinner("🧠 Analyzing security implications..."):
                # Convert profile to structured query for LLM input
                query_parts = []
                for key, value in feature_profile.items():
                    if value and key != "additional_context":
                        query_parts.append(f"{key}: {value}")
                
                if feature_profile.get("additional_context"):
                    query_parts.append(f"Context: {feature_profile['additional_context']}")
                
                query = "\n".join(query_parts)
                
                # Create enhanced narrative query for better CWE/CAPEC retrieval
                narrative_query = format_profile_for_retrieval(feature_profile)
                
                # Use enhanced multi-strategy retrieval
                docs = enhanced_retrieval_multi_strategy(narrative_query, st.session_state.vectorstores, k_per_db=5)
                
                # Generate analysis with clear separation of context and question
                llm, prompt = create_analysis_chain(provider_choice, model_choice, ollama_url)
                
                # Combine documents into context string with better formatting
                context_parts = []
                for i, doc in enumerate(docs):
                    source = doc.metadata.get('source', 'Unknown')
                    # Add source information for better reference tracking
                    context_parts.append(f"Document {i+1} [{source}]: {doc.page_content}")
                
                context_string = "\n\n---\n\n".join(context_parts)
                
                # Format prompt correctly with separate context and question
                formatted_prompt = prompt.format(context=context_string, question=query)
                
                # Get response from LLM
                response = llm.invoke(formatted_prompt)
                
                st.session_state.analysis_result = {
                    "response": response.content,
                    "docs": docs,
                    "feature_profile": feature_profile,
                    "formatted_prompt": formatted_prompt,
                    "provider_used": f"{provider_choice} ({model_choice})"
                }

# Display Results
if "analysis_result" in st.session_state and st.session_state.analysis_result:
    st.divider()
    st.markdown("## 📊 Security Analysis Results")
    
    # Display metadata about the analysis
    meta_col1, meta_col2, meta_col3 = st.columns(3)
    with meta_col1:
        st.caption(f"**Analysis Time (UTC)**: {st.session_state.analysis_result['feature_profile']['timestamp']}")
    with meta_col2:
        st.caption(f"**Analyst**: {st.session_state.analysis_result['feature_profile']['user']}")
    with meta_col3:
        provider_info = st.session_state.analysis_result.get('provider_used', 'Unknown')
        st.caption(f"**Provider**: {provider_info}")
    
    # Main analysis output
    st.markdown(st.session_state.analysis_result["response"])
    
    # Enhanced reference tracking
    response = st.session_state.analysis_result["response"]
    import re
    
    # Extract all references
    cwe_refs = re.findall(r'CWE-(\d+)', response)
    capec_refs = re.findall(r'CAPEC-(\d+)', response)
    asvs_refs = re.findall(r'ASVS-V(\d+(?:\.\d+)?(?:\.\d+)?)', response)
    
    # Show metrics about references
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("CWE References", len(cwe_refs), help="Number of CWE references")
    with col2:
        st.metric("CAPEC References", len(capec_refs), help="Number of CAPEC references")
    with col3:
        st.metric("ASVS References", len(asvs_refs), help="Number of ASVS references")
    
    # Reference documents
    with st.expander("📚 Knowledge Base References"):
        docs = st.session_state.analysis_result["docs"]
        
        # Group by category and show source distribution
        req_docs = [d for d in docs if d.metadata.get("category") == "security_requirements"]
        threat_docs = [d for d in docs if d.metadata.get("category") == "threat_patterns"]
        
        # Show source breakdown
        st.subheader("📊 Source Distribution")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Documents", len(docs))
        with col2:
            st.metric("Security Requirements", len(req_docs))
        with col3:
            st.metric("Threat Patterns", len(threat_docs))
        
        if req_docs:
            st.subheader("🔒 Security Requirements Sources")
            for i, doc in enumerate(req_docs):
                with st.container():
                    st.caption(f"**Source**: {doc.metadata.get('source', 'Unknown')}")
                    st.code(doc.page_content[:300] + "...", language="text")
        
        if threat_docs:
            st.subheader("⚠️ Threat Pattern Sources")  
            for i, doc in enumerate(threat_docs):
                with st.container():
                    source_name = doc.metadata.get('source', '')
                    if 'cwec' in source_name.lower():
                        st.info(f"🎯 CWE Database Source: {source_name}")
                    elif 'capec' in source_name.lower():
                        st.info(f"🎯 CAPEC Database Source: {source_name}")
                    else:
                        st.caption(f"**Source**: {source_name}")
                    st.code(doc.page_content[:300] + "...", language="text")
    
    # Action buttons
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📋 Export Analysis"):
            export_content = f"""
Security Analysis Report
Generated: {st.session_state.analysis_result['feature_profile']['timestamp']}
Analyst: {st.session_state.analysis_result['feature_profile']['user']}

{st.session_state.analysis_result['response']}
"""
            st.download_button(
                "📄 Download as Text",
                export_content,
                file_name=f"security_analysis_{st.session_state.analysis_result['feature_profile']['timestamp'].replace(':', '-').replace(' ', '_')}.txt"
            )
    with col2:
        if st.button("🔄 New Analysis"):
            del st.session_state.analysis_result
            st.experimental_rerun()
    with col3:
        # Add reference verification
        cwe_count = len(cwe_refs)
        capec_count = len(capec_refs)
        asvs_count = len(asvs_refs)
        
        if cwe_count >= 3 and capec_count >= 3 and asvs_count >= 5:
            st.success("✅ All required references present")
        else:
            st.warning(f"⚠️ Missing references: CWE ({cwe_count}/3), CAPEC ({capec_count}/3), ASVS ({asvs_count}/5)")