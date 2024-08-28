import pickle
import numpy as np
from tqdm import tqdm
import requests
from sklearn.metrics.pairwise import cosine_similarity

# 假设这些是您已有的函数和配置
from rag.project_parser import parse_project

API_KEY = "sk-d3i9QpUjDpMo7Qt1C6764388Eb784f7c94D70c904f121435"
API_BASE = "apix.ai-gaochao.cn"
MODEL = "text-embedding-3-large"
EMBEDDINGS_FILE = "vector_database.pkl"

def process_contracts(folder_path):
    all_functions = []
    all_functions,_=parse_project(folder_path)
    return all_functions

def fetch_embedding(text):
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    data = {"input": text, "model": MODEL}
    try:
        response = requests.post(f'https://{API_BASE}/v1/embeddings', json=data, headers=headers)
        response.raise_for_status()
        return response.json()['data'][0]['embedding']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching embedding: {e}")
        return np.zeros(3072).tolist()  # Adjust the size based on your model's output

def generate_embeddings(functions):
    embeddings = {}
    metadata = []
    
    for func in tqdm(functions, desc="Generating embeddings"):
        content = func['content']
        embedding = fetch_embedding(content)
        embeddings[func['name']] = embedding
        metadata.append({
            'content': content,
            'name': func['name'],
            'contract_name': func['contract_name']
        })
    
    return embeddings, metadata

def save_vector_database(embeddings, metadata, output_file):
    with open(output_file, 'wb') as f:
        pickle.dump((embeddings, metadata), f)
    print(f"Vector database saved to {output_file}")

def load_embeddings():
    with open(EMBEDDINGS_FILE, 'rb') as f:
        embeddings, metadata_list = pickle.load(f)
    return embeddings, metadata_list

def get_similar_functions(query_text, embeddings, metadata, top_k=5):
    query_embedding = fetch_embedding(query_text)
    
    similarities = cosine_similarity([query_embedding], list(embeddings.values()))[0]
    top_indices = np.argsort(similarities)[-top_k:][::-1]
    
    results = []
    for idx in top_indices:
        # sim = similarities[idx]
        # if sim < 0.3:
        #     break
        metadata_item = metadata[idx]
        results.append({
            'function_name': metadata_item['name'],
            'contract_name': metadata_item['contract_name'],
            'content': metadata_item['content'],
            'similarity': similarities[idx]
        })
    
    return results

# 主要处理流程
def process_and_create_database(input_folder, output_file):
    print("Processing Solidity contracts...")
    all_functions = process_contracts(input_folder)
    
    print("Generating embeddings...")
    embeddings, metadata = generate_embeddings(all_functions)
    
    print("Saving vector database...")
    save_vector_database(embeddings, metadata, output_file)

# 对外提供的查询接口
def query_similar_functions(query_text, top_k=5):
    embeddings, metadata = load_embeddings()
    return get_similar_functions(query_text, embeddings, metadata, top_k)

# 使用示例
if __name__ == "__main__":
    input_folder = "contracts/shanxuan"
    
    # 处理合约并创建向量数据库
    process_and_create_database(input_folder, EMBEDDINGS_FILE)
    
    # 使用示例查询
    query = "Transfer tokens between accounts"
    results = query_similar_functions(query)
    
    for result in results:
        print(f"Function: {result['function_name']}")
        print(f"Contract: {result['contract_name']}")
        print(f"Similarity: {result['similarity']:.4f}")
        print(f"Content:\n{result['content']}\n")