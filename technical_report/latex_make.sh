#!/bin/bash

latex $1.tex 
bibtex $1.aux
latex $1.tex 
latex $1.tex
dvips $1.dvi 
ps2pdf $1.ps