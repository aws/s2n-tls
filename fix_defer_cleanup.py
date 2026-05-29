import os
import shutil
import re

def process_content(path, content):
    if "s2n_cert_authorities.c" in path:
        content = content.replace('#if S2N_LIBCRYPTO_SUPPORTS_X509_STORE_LIST\n    DEFER_CLEANUP', '#if S2N_LIBCRYPTO_SUPPORTS_X509_STORE_LIST\n{\n    DEFER_CLEANUP')
        content = content.replace('return S2N_RESULT_OK;\n#else', 'return S2N_RESULT_OK;\n}\n#else')

    # Remove #else for EVP_APIS_SUPPORTED since MSVC build is OpenSSL 3.0
    if "s2n_ecc_evp.c" in path:
        lines = content.split('\n')
        out_lines = []
        in_evp = False
        in_else_evp = False
        for line in lines:
            if line.startswith("#if EVP_APIS_SUPPORTED"):
                in_evp = True
                out_lines.append(line)
            elif line.startswith("#else") and in_evp:
                in_else_evp = True
            elif line.startswith("#endif") and in_evp:
                in_else_evp = False
                in_evp = False
                out_lines.append(line)
            else:
                if not in_else_evp:
                    out_lines.append(line)
        content = '\n'.join(out_lines)

    while True:
        match = re.search(r'DEFER_CLEANUP\s*\(', content)
        if not match:
            break
        
        start_idx = match.start()
        
        p_count = 0
        arg_start = match.end()
        end_idx = -1
        for i in range(arg_start, len(content)):
            if content[i] == '(':
                p_count += 1
            elif content[i] == ')':
                if p_count == 0:
                    end_idx = i
                    break
                p_count -= 1
                
        if end_idx == -1:
            break
            
        args_str = content[arg_start:end_idx]
        
        last_comma = args_str.rfind(',')
        if last_comma == -1:
            break
            
        arg1 = args_str[:last_comma].strip()
        arg2 = args_str[last_comma+1:].strip()
        
        var_decl_part = arg1.split('=')[0].strip()
        var_name_match = re.search(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*$', var_decl_part.replace('*', ' '))
        if not var_name_match:
            break
        var_name = var_name_match.group(1)
        
        semi_idx = content.find(';', end_idx)
        if semi_idx == -1:
            break
            
        b_count = 0
        block_end_idx = -1
        for i in range(semi_idx + 1, len(content)):
            if content[i] == '{':
                b_count += 1
            elif content[i] == '}':
                if b_count == 0:
                    block_end_idx = i
                    break
                b_count -= 1
                
        if block_end_idx == -1:
            break
            
        new_content = content[:start_idx] + arg1 + ";\n__try {" + content[semi_idx+1:block_end_idx] + f"}} __finally {{ {arg2}(&{var_name}); }}\n" + content[block_end_idx:]
        content = new_content
        
    return content

def main():
    src_dirs = ["crypto", "error", "stuffer", "tls", "utils", "bin", "tests"]
    out_base = "../auto-win-msvc/rewritten_src"
    
    if not os.path.exists(out_base):
        os.makedirs(out_base)

    for src_dir in src_dirs:
        if not os.path.exists(src_dir):
            continue
        out_dir = os.path.join(out_base, src_dir)
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        shutil.copytree(src_dir, out_dir)
        
        for root, dirs, files in os.walk(out_dir):
            for file in files:
                if file.endswith(".c") or file.endswith(".h"):
                    path = os.path.join(root, file)
                    with open(path, "r", encoding="utf-8") as f:
                        content = f.read()
                    
                    # Pre-process content, whether it has DEFER_CLEANUP or not, to fix braces
                    new_content = process_content(path, content)
                    if new_content != content:
                        with open(path, "w", encoding="utf-8") as f:
                            f.write(new_content)

    with open("CMakeLists.txt", "r", encoding="utf-8") as f:
        cmake_content = f.read()
        
    for src_dir in src_dirs:
        cmake_content = re.sub(
            fr'(?<!rewritten_src/)"{src_dir}/([^"]+)"', 
            fr'"${{CMAKE_CURRENT_LIST_DIR}}/../auto-win-msvc/rewritten_src/{src_dir}/\1"', 
            cmake_content
        )
        
    if "../auto-win-msvc/rewritten_src" not in cmake_content:
        cmake_content = cmake_content.replace(
            'target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)',
            'target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../auto-win-msvc/rewritten_src> $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)'
        )

    with open("CMakeLists.txt", "w", encoding="utf-8") as f:
        f.write(cmake_content)

if __name__ == "__main__":
    main()