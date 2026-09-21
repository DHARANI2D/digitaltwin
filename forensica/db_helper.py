# db_helper.py
import os
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor
import json

class DatabaseHelper:
    def __init__(self, dsn=None):
        self.dsn = dsn or os.environ.get("POSTGRES_URL")
        self.use_sqlite = False
        self.conn = None
        self._init_connection()

    def _init_connection(self):
        if self.dsn:
            try:
                self.conn = psycopg2.connect(self.dsn)
                self.conn.autocommit = True
                print("[DatabaseHelper] Connected to PostgreSQL.")
                return
            except Exception as e:
                print(f"[DatabaseHelper] PostgreSQL connection failed: {e}. Falling back to SQLite.")
        
        # Fallback to SQLite
        self.use_sqlite = True
        sqlite_db = "forensica.db"
        self.conn = sqlite3.connect(sqlite_db, check_same_thread=False, timeout=30.0)
        self._init_sqlite_schema()
        print(f"[DatabaseHelper] Connected to SQLite (database file: {sqlite_db}).")

    def _init_sqlite_schema(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                evidence_path TEXT,
                risk_score INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                timestamp TEXT,
                source TEXT,
                event_type TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                claim TEXT,
                confidence INTEGER,
                artifacts TEXT,
                source_agent TEXT,
                is_validated BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                ioc_value TEXT,
                ioc_type TEXT,
                source_agent TEXT,
                confidence INTEGER,
                enrichment_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                rule_name TEXT,
                content TEXT,
                rule_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT REFERENCES cases(case_id) ON DELETE CASCADE,
                report_type TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self.conn.commit()

    def execute_query(self, query, params=None):
        cursor = self.conn.cursor()
        if self.use_sqlite:
            # SQLite uses ? instead of %s or $name
            query = query.replace("%s", "?")
            cursor.execute(query, params or ())
            self.conn.commit()
            return cursor
        else:
            cursor.execute(query, params or ())
            return cursor

    def insert_case(self, case_id, evidence_path, risk_score=0):
        query = """
            INSERT INTO cases (case_id, evidence_path, risk_score)
            VALUES (%s, %s, %s)
            ON CONFLICT (case_id) DO UPDATE SET risk_score = EXCLUDED.risk_score;
        """
        if self.use_sqlite:
            # For SQLite ON CONFLICT
            query = """
                INSERT OR REPLACE INTO cases (case_id, evidence_path, risk_score)
                VALUES (%s, %s, %s);
            """
        self.execute_query(query, (case_id, evidence_path, risk_score))

    def insert_event(self, case_id, timestamp, source, event_type, details):
        details_str = json.dumps(details)
        query = """
            INSERT INTO events (case_id, timestamp, source, event_type, details)
            VALUES (%s, %s, %s, %s, %s);
        """
        self.execute_query(query, (case_id, timestamp, source, event_type, details_str))

    def insert_finding(self, case_id, claim, confidence, artifacts, source_agent, is_validated=True):
        art_str = json.dumps(artifacts)
        query = """
            INSERT INTO findings (case_id, claim, confidence, artifacts, source_agent, is_validated)
            VALUES (%s, %s, %s, %s, %s, %s);
        """
        self.execute_query(query, (case_id, claim, confidence, art_str, source_agent, 1 if is_validated else 0))

    def insert_ioc(self, case_id, ioc_value, ioc_type, source_agent, confidence, enrichment_data):
        enr_str = json.dumps(enrichment_data)
        query = """
            INSERT INTO iocs (case_id, ioc_value, ioc_type, source_agent, confidence, enrichment_data)
            VALUES (%s, %s, %s, %s, %s, %s);
        """
        self.execute_query(query, (case_id, ioc_value, ioc_type, source_agent, confidence, enr_str))

    def insert_detection(self, case_id, rule_name, content, rule_type):
        query = """
            INSERT INTO detections (case_id, rule_name, content, rule_type)
            VALUES (%s, %s, %s, %s);
        """
        self.execute_query(query, (case_id, rule_name, content, rule_type))

    def insert_report(self, case_id, report_type, content):
        query = """
            INSERT INTO reports (case_id, report_type, content)
            VALUES (%s, %s, %s);
        """
        self.execute_query(query, (case_id, report_type, content))

    def get_events(self, case_id):
        query = "SELECT timestamp, source, event_type, details FROM events WHERE case_id = %s"
        cursor = self.execute_query(query, (case_id,))
        rows = cursor.fetchall()
        events = []
        for r in rows:
            events.append({
                "timestamp": r[0],
                "source": r[1],
                "event_type": r[2],
                "details": json.loads(r[3])
            })
        return events

    def get_findings(self, case_id):
        query = "SELECT claim, confidence, artifacts, source_agent, is_validated FROM findings WHERE case_id = %s"
        cursor = self.execute_query(query, (case_id,))
        rows = cursor.fetchall()
        findings = []
        for r in rows:
            findings.append({
                "claim": r[0],
                "confidence": r[1],
                "artifacts": json.loads(r[2]),
                "source_agent": r[3],
                "is_validated": bool(r[4])
            })
        return findings

    def get_iocs(self, case_id):
        query = "SELECT ioc_value, ioc_type, source_agent, confidence, enrichment_data FROM iocs WHERE case_id = %s"
        cursor = self.execute_query(query, (case_id,))
        rows = cursor.fetchall()
        iocs = []
        for r in rows:
            iocs.append({
                "ioc_value": r[0],
                "ioc_type": r[1],
                "source_agent": r[2],
                "confidence": r[3],
                "enrichment_data": json.loads(r[4])
            })
        return iocs


import math
import re

class SimpleVectorStore:
    """
    Lightweight vector store implementing a pure Python TF-IDF and 
    Cosine Similarity retrieval model for MITRE mapping and case searches.
    """
    def __init__(self):
        self.documents = [] # list of dicts: {"text": str, "metadata": dict}

    def add_document(self, text, metadata=None):
        self.documents.append({"text": text, "metadata": metadata or {}})

    def _tokenize(self, text):
        # Lowercase, remove punctuation and split
        text_clean = re.sub(r'[^\w\s]', ' ', text.lower())
        return [w for w in text_clean.split() if w]

    def search(self, query, limit=3):
        if not self.documents:
            return []

        # 1. Tokenize all documents
        doc_tokens = [self._tokenize(doc["text"]) for doc in self.documents]
        num_docs = len(self.documents)

        # 2. Build vocabulary and Document Frequencies (DF)
        vocab = set()
        df = {}
        for tokens in doc_tokens:
            unique_terms = set(tokens)
            vocab.update(unique_terms)
            for term in unique_terms:
                df[term] = df.get(term, 0) + 1

        # 3. Calculate IDF for each term in vocabulary
        idf = {}
        for term in vocab:
            # Add-one smoothing to avoid division by zero
            idf[term] = math.log(1 + (num_docs / (1 + df[term])))

        # 4. Compute TF-IDF vectors for all documents
        doc_vectors = []
        for tokens in doc_tokens:
            tf = {}
            for token in tokens:
                tf[token] = tf.get(token, 0) + 1
            
            # Build vector dictionary (only store non-zero values to save space)
            vector = {}
            for term, count in tf.items():
                vector[term] = count * idf[term]
            doc_vectors.append(vector)

        # 5. Tokenize query and build query vector
        query_tokens = self._tokenize(query)
        query_tf = {}
        for token in query_tokens:
            query_tf[token] = query_tf.get(token, 0) + 1

        query_vector = {}
        for term, count in query_tf.items():
            if term in idf:
                query_vector[term] = count * idf[term]

        # If query has no words matching vocabulary, return first documents by default
        if not query_vector:
            return self.documents[:limit]

        # 6. Calculate Cosine Similarity for each document
        # Norm of query vector
        query_norm = math.sqrt(sum(val ** 2 for val in query_vector.values()))
        if query_norm == 0:
            return self.documents[:limit]

        results = []
        for idx, doc_vector in enumerate(doc_vectors):
            # Dot product
            dot_product = 0.0
            for term, val in query_vector.items():
                if term in doc_vector:
                    dot_product += val * doc_vector[term]

            # Norm of document vector
            doc_norm = math.sqrt(sum(val ** 2 for val in doc_vector.values()))
            
            # Cosine similarity score
            score = 0.0
            if doc_norm > 0:
                score = dot_product / (query_norm * doc_norm)
                
            results.append((score, self.documents[idx]))

        # Sort by similarity score descending
        results.sort(key=lambda x: x[0], reverse=True)
        return [res[1] for res in results[:limit]]

