from flask import Flask, render_template_string
import json
import os
from pathlib import Path

app = Flask(__name__)

# Path to outputs folder
OUTPUTS_DIR = Path(__file__).parent / "outputs"

def load_json_files():
    """Load all JSON files from outputs folder"""
    tables = {}
    if OUTPUTS_DIR.exists():
        for file in OUTPUTS_DIR.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    tables[file.stem] = json.load(f)
            except Exception as e:
                print(f"Error loading {file}: {e}")
    return tables

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>StackForge Visualizer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .tabs { display: flex; gap: 10px; border-bottom: 2px solid #ccc; margin-bottom: 20px; }
        .tab-btn { padding: 10px 20px; cursor: pointer; border: none; background: #f0f0f0; }
        .tab-btn.active { background: #007bff; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>StackForge Visualizer</h1>
    <div class="tabs">
        {% for name in tables.keys() %}
            <button class="tab-btn {% if loop.first %}active{% endif %}" onclick="showTab('{{ name }}')">
                {{ name }}
            </button>
        {% endfor %}
    </div>
    
    {% for name, data in tables.items() %}
        <div class="tab-content {% if loop.first %}active{% endif %}" id="tab-{{ name }}">
            <h2>{{ name }}</h2>
            {% if data is string %}
                <pre>{{ data }}</pre>
            {% else %}
                <table>
                    <thead>
                        <tr>
                            {% for key in data[0].keys() %}
                                <th>{{ key }}</th>
                            {% endfor %}
                        </tr>
                    </thead>
                    <tbody>
                        {% for row in data %}
                            <tr>
                                {% for value in row.values() %}
                                    <td>{{ value }}</td>
                                {% endfor %}
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% endif %}
        </div>
    {% endfor %}
    
    <script>
        function showTab(name) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + name).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    tables = load_json_files()
    return render_template_string(HTML_TEMPLATE, tables=tables)

if __name__ == '__main__':
    app.run(debug=True, port=5000)