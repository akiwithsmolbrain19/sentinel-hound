.PHONY: test lint security check demo

test:
	python3 -m unittest discover -s tests -v

lint:
	python3 -m py_compile $$(git ls-files '*.py')

security:
	grep -rniE 'aws_secret|BEGIN [A-Z ]*PRIVATE KEY|password\s*=\s*["'\''][^"'\'']+["'\'']' --include='*.py' --include='*.json' --include='*.yaml' --include='*.md' . | grep -v sample_data || true
	python3 -c "import json; [json.load(open(f)) for f in ['config/rules.json','config/iocs.json','config/allowlist.json']]; print('configs parse OK')"

check: test lint security

demo:
	python3 -m sentinel_hound.cli analyze --auth-log sample_data/auth.log --access-log sample_data/access.log --db /tmp/sentinel-demo.db
	python3 -m sentinel_hound.cli cases list --db /tmp/sentinel-demo.db
