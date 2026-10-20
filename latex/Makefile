# Compilación del Reporte del Proyecto Integrador
# Uso:  make            -> compila y genera ReportePI.pdf
#       make clean      -> borra archivos auxiliares
#       make distclean  -> borra auxiliares + PDF
#       make view       -> abre el PDF

MAIN    := ReportePI.tex
PDF     := ReportePI.pdf
LATEXMK := latexmk -xelatex -interaction=nonstopmode -file-line-error

.PHONY: all clean distclean view bib

all: $(PDF)

$(PDF): $(MAIN) cap01.tex cap02.tex cap03.tex cap04.tex cap05.tex resumen.tex \
        abreviaturas.tex simbologia.tex adicionales.tex apendices.tex title.tex referencias.bib
	$(LATEXMK) $(MAIN)
	@echo ""
	@echo "==> PDF generado: $(PDF)"

# Regenera solo la bibliografía (Biber)
bib:
	biber $(basename $(MAIN))

clean:
	$(LATEXMK) -c $(MAIN)
	@echo "==> Auxiliares eliminados."

distclean: clean
	rm -f $(PDF)
	@echo "==> PDF eliminado."

view: $(PDF)
	xdg-open $(PDF) 2>/dev/null || evince $(PDF) 2>/dev/null || echo "Abre $(PDF) manualmente."
