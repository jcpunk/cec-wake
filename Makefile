current_dir:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
version:=$(shell git describe --tags --abbrev=0 2>/dev/null || grep -m 1 'version = ' pyproject.toml | sed 's/.*version = "//' | sed 's/".*//')
name:=cec-wake
PYTHON:=python3

_default:
	@echo "Perhaps you want:"
	@echo "make zipapp    - Build the cec_wake_daemon zipapp in-tree"
	@echo "make sources   - Create source tarball for koji"
	@echo "make srpm      - Build source RPM locally"
	@echo "make rpm       - Build binary RPM locally"
	@echo "make test      - Run the unit test suite with coverage"
	@echo "make lint      - Run ruff + mypy"

zipapp:
	@echo "Building cec_wake_daemon zipapp"
	rm -rf BUILD/zipapp-src
	mkdir -p BUILD/zipapp-src
	cp -r src/cec_wake BUILD/zipapp-src/
	find BUILD/zipapp-src -name '__pycache__' -prune -exec rm -rf {} +
	$(PYTHON) -m zipapp BUILD/zipapp-src -m "cec_wake.cli:main" \
		-p "/usr/bin/python3" -o cec_wake_daemon --compress

sources:
	@echo "Creating source tarball for koji"
	@tmpdir=$$(mktemp -d); \
	set -e; \
	git archive --format=tar --prefix=$(name)-$(version)/ HEAD > "$$tmpdir/src.tar"; \
	gzip --best -c "$$tmpdir/src.tar" > "$(current_dir)/$(name)-$(version).tar.gz"; \
	rm -rf "$$tmpdir"

srpm: sources
	@echo "Building source RPM"
	rpmbuild -bs --define '_sourcedir $(current_dir)' --define '_srcrpmdir $(current_dir)/SRPMS' $(name).spec

rpm: sources
	@echo "Building binary RPM"
	rpmbuild -bb --define '_rpmdir $(current_dir)/RPMS' --define '_builddir $(current_dir)/BUILD' --define '_sourcedir $(current_dir)' $(name).spec

test:
	uv run pytest

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests
	uv run mypy

.PHONY: _default zipapp sources srpm rpm test lint
