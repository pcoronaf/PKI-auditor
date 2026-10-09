#!/bin/sh
# Regenera bundle.min.js a partir de las fuentes de demo-key-exfiltration.
#
# Reproduce lo que haria un bundler en un despliegue real: las fuentes en un
# unico ambito (IIFE) y terser con compresion y mangle, de modo que todos los
# nombres locales -- keyBytes, password, toBase64... -- desaparecen. Las
# cadenas literales y los ids del HTML ("key-file", "password") sobreviven,
# como en la realidad. Del PR #2.
#
#   sh build.sh        (usa npx terser@5)
set -e
here=$(dirname "$0")
{
  echo '(function(){'
  cat "$here/../shared/efirma.js" "$here/../shared/flow.js" "$here/../demo-key-exfiltration/app.js"
  echo '})();'
} | npx --yes terser@5 --compress --mangle --toplevel \
      --format 'preamble="/* demo-minified: generado por build.sh con terser; no editar a mano. */"' \
      -o "$here/bundle.min.js"
