#
# Makefile — build de los 5 libros de documentación GraphHunter
#
# Uso:
#   make arquitectura
#   make especificacion
#   make manual
#   make paper
#   make diseno
#   make all
#   make clean
#
# Requisitos: xelatex (TeX Live / MiKTeX) y biber (sólo para el paper).

LATEX      := xelatex
LATEX_OPTS := -shell-escape -interaction=nonstopmode -halt-on-error
BIBER      := biber

BOOKS := arquitectura especificacion manual paper diseno

.PHONY: all clean $(BOOKS)

all: $(BOOKS)

# Libros sin bibliografía: dos pasadas para resolver TOC + refs cruzadas.
arquitectura especificacion manual diseno:
	cd $@ && $(LATEX) $(LATEX_OPTS) main.tex && $(LATEX) $(LATEX_OPTS) main.tex
	@mv $@/main.pdf $@/$@.pdf 2>/dev/null || true

# Paper con biber: xelatex, biber, xelatex x2.
paper:
	cd paper && $(LATEX) $(LATEX_OPTS) main.tex
	cd paper && $(BIBER) main || true
	cd paper && $(LATEX) $(LATEX_OPTS) main.tex
	cd paper && $(LATEX) $(LATEX_OPTS) main.tex
	@mv paper/main.pdf paper/paper.pdf 2>/dev/null || true

clean:
	@for dir in $(BOOKS); do \
	  rm -f $$dir/*.aux $$dir/*.log $$dir/*.out $$dir/*.toc $$dir/*.lof $$dir/*.lot \
	        $$dir/*.idx $$dir/*.ilg $$dir/*.ind $$dir/*.bbl $$dir/*.bcf $$dir/*.blg \
	        $$dir/*.run.xml $$dir/*.synctex.gz $$dir/*.fdb_latexmk $$dir/*.fls; \
	  rm -f $$dir/chapters/*.aux $$dir/sections/*.aux $$dir/appendices/*.aux 2>/dev/null; \
	done
