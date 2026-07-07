# Build the algorithm reference PDF.
#
# Run:   make
# Clean: make clean

MAIN = main
PDFLATEX = pdflatex -interaction=nonstopmode -halt-on-error

$(MAIN).pdf: $(MAIN).tex preamble.tex
	$(PDFLATEX) $(MAIN)
	$(PDFLATEX) $(MAIN)
	$(PDFLATEX) $(MAIN)

.PHONY: clean
clean:
	rm -f $(MAIN).aux $(MAIN).log $(MAIN).toc $(MAIN).out \
	      $(MAIN).lof $(MAIN).lot $(MAIN).idx $(MAIN).ilg \
	      $(MAIN).ind $(MAIN).bbl $(MAIN).blg

.PHONY: distclean
distclean: clean
	rm -f $(MAIN).pdf
