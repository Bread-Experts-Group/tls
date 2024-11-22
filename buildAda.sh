#!/bin/bash
alr exec -- gnatpp -Ptls.gpr --max-line-length=179 --wide-character-encoding=8 --eol=lf -k --layout=tall -U; alr build --profiles=*=$1 -- ${@:2}