import os
import re
import shutil
import argparse

# Pattern to match SSI include directives
INCLUDE_PATTERN = re.compile(r'<!--#include\s+virtual="([^"]+)"\s*-->')

def process_file(file_path, base_dir):
    """
    Reads a file and replaces any SSI include directives with the content
    of the included file. If the included file is '/config.js', it is loaded
    from '/etc/jitsi/meet/jitsi.nym.re-config.js'.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    def replace_include(match):
        include_virtual = match.group(1)

        # Exception: if the include is exactly /config.js, load from /etc/jitsi/meet/jitsi.nym.re-config.js.
        if include_virtual == '/config.js':
            include_path = '/etc/jitsi/meet/jitsi.nym.re-config.js'
        elif include_virtual.startswith('/'):
            include_path = os.path.join(base_dir, include_virtual.lstrip('/'))
        else:
            include_path = os.path.join(os.path.dirname(file_path), include_virtual)

        if os.path.exists(include_path):
            with open(include_path, 'r', encoding='utf-8') as inc_file:
                return inc_file.read()
        else:
            print(f"Warning: Included file {include_path} not found.")
            return f"<!-- Missing file: {match.group(1)} -->"

    # Replace all SSI include directives with file content
    return INCLUDE_PATTERN.sub(replace_include, content)

def extract_inline_scripts(html_content, out_dir, base_name):
    """
    Searches for inline <script>...</script> blocks (that do not already have a src attribute)
    in the html content, writes the JavaScript code into external files (named using the base_name),
    and replaces each inline block with an external reference.
    """
    # Pattern to match any <script> block.
    # The (?P<attrs>...) captures attributes inside the opening tag.
    # The (?P<content>.*?) captures the script content.
    script_pattern = re.compile(
        r'<script(?P<attrs>[^>]*?)>(?P<content>.*?)</script>',
        re.DOTALL | re.IGNORECASE
    )

    counter = 0  # Used to create unique file names for inline scripts

    def repl(match):
        nonlocal counter
        attrs = match.group('attrs')
        content = match.group('content')

        # If there is a src attribute in the tag then leave it unchanged.
        if re.search(r'\bsrc\s*=', attrs, re.IGNORECASE):
            return match.group(0)

        # If the inline content is empty or only whitespace, no need to externalize.
        if not content.strip():
            return match.group(0)

        counter += 1
        # Create a unique script filename in the same directory as the html file.
        script_filename = f"{base_name}_inline_{counter}.js"
        script_path = os.path.join(out_dir, script_filename)
        with open(script_path, 'w', encoding='utf-8') as js_file:
            js_file.write(content)

        # Optionally, preserve any attributes (other than inline content)
        new_attrs = attrs.strip()
        # Build the new <script> tag that loads the external file.
        return f'<script {new_attrs} src="{script_filename}"></script>' if new_attrs else f'<script src="{script_filename}"></script>'

    # Substitute inline script blocks with external ones.
    modified_html = script_pattern.sub(repl, html_content)
    return modified_html

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
                # First, process SSI includes.
                processed_content = process_file(file_path, source_dir)
                # Then, extract inline script blocks.
                # Pass the output directory (for the HTML file) and the base name of the HTML file
                # so that the external js files are created alongside.
                out_dir_for_html = os.path.dirname(output_path)
                base_name = os.path.splitext(os.path.basename(output_path))[0]
                modified_content = extract_inline_scripts(processed_content, out_dir_for_html, base_name)

                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(modified_content)
                print(f"Processed {relative_path} -> {output_path}")
            else:
                shutil.copy2(file_path, output_path)
                print(f"Copied {relative_path} -> {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build static site by processing SSI includes and externalizing inline scripts for CSP compliance.")
    parser.add_argument('source', help="Source directory with SSI files")
    parser.add_argument('destination', help="Destination directory for static output")
    args = parser.parse_args()

    build_static_site(args.source, args.destination)
    print("Static site build complete.")
