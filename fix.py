import io
with io.open('ui/index.html', 'r', encoding='utf-8') as f:
    text = f.read()

# Remove the literal backslashes that were escaping the template literals
text = text.replace('\\`', '`')
text = text.replace('\\${', '${')

with io.open('ui/index.html', 'w', encoding='utf-8') as f:
    f.write(text)
