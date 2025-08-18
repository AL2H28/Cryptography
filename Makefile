MODULE := src

# Colours for printing
E_BLUE=$(shell echo -e "\033[0;34m")
E_END=$(shell echo -e "\033[0m")
E_RED=$(shell echo -e "\033[0;31m")
E_YELLOW=$(shell echo -e "\033[0;33m")

.DEFAULT_GOAL = help

ACTIVATE = . .venv/bin/activate


help: ## Show all commands
	@egrep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "${E_BLUE}%-15s${E_END} %s\n", $$1, $$2}'


install: ## Create environment, upgrade pip and install requirements
	@echo "${E_BLUE}Creating environment...${E_END}"
	@python3 -m venv .venv
	@echo "${E_BLUE}Upgrading pip...${E_END}"
	@venv/bin/pip install --upgrade pip             \
		--trusted-host pypi.org                 \
		--trusted-host pypi.python.org          \
		--trusted-host=files.pythonhosted.org   \

	@echo "${E_BLUE}Installing...${E_END}"
	@venv/bin/pip install --no-cache-dir -r requirements.txt        \
		--trusted-host pypi.org                 \
		--trusted-host pypi.python.org          \
		--trusted-host=files.pythonhosted.org   \



test: ## Run the tests always to check implementation
	@echo "${E_BLUE}Testing...${E_END}"
	@$(ACTIVATE); pytest -vv


lint: ## Lint code to see if implementation follows coding standards
	@echo "${E_BLUE}Running pylint...${E_END}"
	@$(ACTIVATE); pylint --rcfile=setup.cfg $(MODULE)
	@echo "${E_BLUE}Running flake8...${E_END}"
	@$(ACTIVATE); flake8
	@echo "${E_BLUE}Running bandit...${E_END}"
	@$(ACTIVATE); bandit -r --ini setup.cfg


docs: ## Create documentation
	@echo "${E_BLUE}Creating documentation...${E_END}"
	@$(ACTIVATE); pdoc --docformat google src -o docs


clean: ## Clean up by removing caches
	@echo "${E_BLUE}Removing caches...${E_END}"
	@rm -rf .pytest_cache .coverage .pytest_cache  coverage.xml
	@find . -type d -name __pycache__ -exec rm -rf {} \+


.PHONY: clean test install version docs run