import os
import re
import shutil
import argparse

# Pattern to match SSI include directives
INCLUDE_PATTERN = re.compile(r'<!--#include\s+virtual="([^"]+)"\s*-->')

def process_file(file_path, base_dir):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    def replace_include(match):
        include_path = match.group(1)
        # Handle paths starting with '/' as relative to the base_dir
        if include_path.startswith('/'):
            include_path = os.path.join(base_dir, include_path.lstrip('/'))
        else:
            include_path = os.path.join(os.path.dirname(file_path), include_path)

        if os.path.exists(include_path):
            with open(include_path, 'r', encoding='utf-8') as inc_file:
                return inc_file.read()
        else:
            print(f"Warning: Included file {include_path} not found.")
            return f"<!-- Missing file: {match.group(1)} -->"

    # Replace all SSI include directives with file content
    return INCLUDE_PATTERN.sub(replace_include, content)

def build_static_site(source_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for root, _, files in os.walk(source_dir):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, source_dir)
            output_path = os.path.join(output_dir, relative_path)

            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            if file.endswith('.html'):
                processed_content = process_file(file_path, source_dir)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(processed_content)
                print(f"Processed {relative_path} -> {output_path}")
            else:
                shutil.copy2(file_path, output_path)
                print(f"Copied {relative_path} -> {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build static site by processing SSI includes.")
    parser.add_argument('source', help="Source directory with SSI files")
    parser.add_argument('destination', help="Destination directory for static output")
    args = parser.parse_args()

    build_static_site(args.source, args.destination)
    print("Static site build complete.")
