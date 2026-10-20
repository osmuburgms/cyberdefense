# Configuración de latexmk idéntica a la receta de Overleaf:
# Compilador: XeLaTeX  ->  $pdf_mode = 5
# Bibliografía: Biber   ->  detectado automáticamente por el archivo .bcf
$pdf_mode = 5;
$biber_use = 1;
$max_repeat = 5;
$clean_ext = "aux bbl bcf blg brf fdb_latexmk fls log loa lol lot lof out run.xml synctex.gz toc xdv";

# Evita que latexmk se detenga en errores de referencia cruzada
@default_files = ("ReportePI.tex");
