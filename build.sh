#!/bin/bash

function error_exit
{
	echo "$1" 1>&2
	exit 1
}

source `which virtualenvwrapper.sh` || error_exit "No Python virtualenvwrapper found"

mktmpenv -n || error_exit "Could not create temporary environment"
pip install -r requirements.txt || error_exit "Could not install Python requirements"
pip install setuptools==19.2 || error_exit "setuptools==19.2 required for pyinstaller"
pip install pyinstaller==2.1 || error_exit "could not install pyinstaller"

python setup.py bdist_binaryrpm || error_exit "could not build RPM"
deactivate
