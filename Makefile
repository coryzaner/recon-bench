# Ethical recon/test bench — one-command targets.
INV ?= inventory.yml
LIMIT ?= testbench

.PHONY: deploy check lint test syntax compose-build help
help:
	@echo "make deploy   - stand up the bench on the lab VM (one command)"
	@echo "make check    - ansible dry-run (--check --diff)"
	@echo "make lint     - yamllint + ansible-lint"
	@echo "make test     - local safety-gate unit tests (no VM needed)"
	@echo "make syntax   - ansible-playbook --syntax-check"

deploy:
	ansible-playbook -i $(INV) site.yml --limit $(LIMIT)
check:
	ansible-playbook -i $(INV) site.yml --limit $(LIMIT) --check --diff
syntax:
	ansible-playbook -i inventory.example.yml site.yml --syntax-check
lint:
	yamllint .
	ansible-lint
test:
	bash tests/gate_test.sh
compose-build:
	docker compose -f compose/docker-compose.yml config
