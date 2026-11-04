# Compilación del Reporte del Proyecto Integrador
#
# Flujo para actualizar el diagrama y el reporte:
#   1)  make fig    -> genera recursos/Ciberdefense_despues_diagrama.pdf desde el SVG
#   2)  make        -> compila ReportePI.pdf (usando el diagrama ya regenerado)
#
# También:  make            -> si el SVG cambió, hace el paso 1 y luego el 2 automáticamente
#           make clean      -> borra archivos auxiliares
#           make distclean  -> borra auxiliares + PDF
#           make view       -> abre el PDF

# Entorno de compilación local (TinyTeX sin root + perl/libcrypt de conda).
# Si alguna carpeta no existe, PATH queda intacto y make usa el TeX del sistema.
export PATH := $(HOME)/.local/bin:$(HOME)/.TinyTeX/bin/x86_64-linux:$(HOME)/.local/texenv/bin:$(PATH)
export LC_ALL := C

MAIN    := ReportePI.tex
PDF     := ReportePI.pdf
SVG     := recursos/CyberDefense_despues_diagrama.svg
FIGPDF  := recursos/Ciberdefense_despues_diagrama.pdf
LATEXMK := latexmk -xelatex -interaction=nonstopmode -file-line-error

.PHONY: all fig clean distclean view bib

all: $(PDF)

# Regenera el diagrama PDF cuando el SVG cambio y compila el reporte
$(FIGPDF): $(SVG)
	rsvg-convert -f pdf -o $@ $<
	@echo "==> Diagrama regenerado: $@"

$(PDF): $(MAIN) cap01.tex cap02.tex cap03.tex cap04.tex cap05.tex resumen.tex \
        abreviaturas.tex simbologia.tex adicionales.tex apendices.tex title.tex referencias.bib \
        $(FIGPDF)
	$(LATEXMK) $(MAIN)
	@echo ""
	@echo "==> PDF generado: $(PDF)"

# Paso 1: genera el PDF de la imagen desde el SVG.
#	- Si el SVG fue guardado DESPUES del PDF actual -> lo regenera.
#	- Si no hay cambios nuevos te lo avisa en lugar de quedarse en silencio.
fig:
	@if [ "$(SVG)" -nt "$(FIGPDF)" ]; then \
	  echo "==> SVG más nuevo que el PDF: regenerando $(FIGPDF)..."; \
	  rsvg-convert -f pdf -o "$(FIGPDF)" "$(SVG)"; \
	  echo "==> Diagrama regenerado: $(FIGPDF)"; \
	else \
	  echo "==> Nada que regenerar: $(FIGPDF) ya está al día con el SVG."; \
	  echo "    (Guarda los cambios del SVG en Inkscape/VS Code y vuelve a correr 'make fig')"; \
	fi

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
