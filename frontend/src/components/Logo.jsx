import logoIconRaw from '../assets/cyberdefense_logo.svg?raw';
import logoHorizontalRaw from '../assets/cyberdefense_logo_horizontal.svg?raw';

// Los SVG oficiales vienen firmados con C2PA: el bloque <metadata> ocupa ~9 KB
// por archivo y no aporta nada al renderizado, así que se quita del bundle.
// El resto del SVG (geometría y paleta) se respeta tal cual.
const stripManifest = (svg) =>
  svg
    .replace(/<\?xml[^>]*\?>\s*/, '') // la declaración XML no vale dentro de HTML
    .replace(/<metadata>[\s\S]*?<\/metadata>/g, '');

const ICON_SVG = stripManifest(logoIconRaw);
const HORIZONTAL_SVG = stripManifest(logoHorizontalRaw);

// Logotipo vertical (escudo) de CyberDefense AI.
// El SVG se inserta en línea (no como <img>) para poder repintar el texto del
// lockup horizontal en modo claro desde CSS, donde cualquier regla CSS gana al
// atributo de presentación fill="..." del propio SVG.
// El <svg> ya lleva role="img" y su aria-label, así que el envoltorio queda
// marcado como decorativo para no duplicar el nombre accesible.
export function LogoIcon({ className = '' }) {
  return (
    <span
      aria-hidden="true"
      className={`cd-logo cd-logo--icon ${className}`}
      dangerouslySetInnerHTML={{ __html: ICON_SVG }}
    />
  );
}

// Lockup horizontal: escudo + "CyberDefense AI" + lema.
export function LogoHorizontal({ className = '' }) {
  return (
    <span
      aria-hidden="true"
      className={`cd-logo cd-logo--horizontal ${className}`}
      dangerouslySetInnerHTML={{ __html: HORIZONTAL_SVG }}
    />
  );
}

export default LogoIcon;
