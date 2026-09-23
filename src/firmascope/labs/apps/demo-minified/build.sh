#!/bin/sh
# Regenera bundle.min.js a partir de las fuentes de demo-key-exfiltration.
#
# Reproduce lo que haria un bundler en un despliegue real: las tres fuentes en
# un unico ambito (IIFE) y terser con compresion y mangle, de modo que todos
# los nombres locales — keyBytes, password, toBase64... — desaparecen. Las
# cadenas literales ("password", "/collect/key") sobreviven, como en la
# realidad.
#
#   npm install terser@5 && sh build.sh
set -e
here=$(dirname "$0")
{
  echo '(function(){'
  cat "$here/../shared/efirma.js" "$here/../shared/lab.js" "$here/../demo-key-exfiltration/app.js"
  echo '})();'
} | npx terser --compress --mangle --toplevel \
      --format 'preamble="/* demo-minified: generado por build.sh con terser; no editar a mano. */"' \
      -o "$here/bundle.min.js"
