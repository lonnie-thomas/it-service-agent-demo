PYTHON ?= python3
VENV   ?= .venv

.PHONY: install test demo demo-injection verify-runbooks manifest clean

install:            ## create a virtualenv and install the package + test tools
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -e . -r requirements.txt

test:               ## run the offline test suite
	$(VENV)/bin/python -m pytest

demo:               ## end-to-end demo: triage -> refused -> approve -> execute -> replay refused -> audit verify
	PYTHON=$(VENV)/bin/python ./scripts/demo.sh

demo-injection:     ## same flow on the prompt-injection sample ticket
	PYTHON=$(VENV)/bin/python ./scripts/demo.sh examples/tickets/INC-1005-INJECTION-DEMO.json

manifest:           ## re-pin runbook hashes after a REVIEWED runbook change
	$(VENV)/bin/python -m it_service_agent manifest

clean:
	rm -rf .itsa .itsa-demo .pytest_cache build *.egg-info
