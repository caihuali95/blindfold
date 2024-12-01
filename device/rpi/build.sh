#!/bin/sh

RPI=$(pwd)
BF=$RPI/../..

BF=$BF $RPI/build_linux.sh
BF=$BF $RPI/build_guardian.sh
BF=$BF $RPI/build_armtf.sh
BF=$BF $RPI/build_app.sh
