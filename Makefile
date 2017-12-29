.DEFAULT_GOAL := help

help:             ## Show available options with this Makefile
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY : test
test:             ## Run all the tests
test:
	python setup.py test

.PHONY : recreate_pyenv
recreate_pyenv:   ## Create the python environment. Recreates if the env exists already.
recreate_pyenv:
	conda env create --force -f dev_environment.yml
