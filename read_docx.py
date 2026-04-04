import zipfile
import xml.etree.ElementTree as ET

def extract(path):
    with zipfile.ZipFile(path) as docx:
        xml_content = docx.read('word/document.xml')
        tree = ET.fromstring(xml_content)
        ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
        text = []
        for p in tree.findall('.//w:p', ns):
            t_nodes = p.findall('.//w:t', ns)
            if t_nodes:
                text.append(''.join([n.text for n in t_nodes if n.text]))
        return '\n'.join(text)

with open('extracted_docx.txt', 'w', encoding='utf-8') as f:
    f.write(extract(r'e:\ALLCAPSNOSMALL\Docs\AiSocAnalyzer_UI_PromptBook.docx'))
