python3 -m venv soc_env
source soc_env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip freeze > requirements-lock.txt
echo 'Environment ready.'
