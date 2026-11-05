# Origen

`graphhunter_defensa` junta dos proyectos previos del mismo autor bajo Graph
Hunter. El código de cada uno se copió y después se renombró por función;
este archivo es el único registro de dónde vino.

- `cobertura/` y `cobertura/tests/`: copia de `detcover`
  (github.com/sotomayorlucas/detcover, commit 70b6a13, licencia MIT). Se
  copiaron la biblioteca y sus tests, no los experimentos ni los resultados.
- `ad/graph.py`, `ad/bloodhound.py`, `ad/sharphound.py`, `ad/adgen.py`,
  `recolector/attacker.py` y `recolector/game.py`: copia de `periplo`
  (github.com/sotomayorlucas/periplo, commit 1456ec1, licencia MIT), sin
  cambios de lógica salvo los imports.

Los dos se relicencian bajo la licencia de este repo, salvo
`cobertura/dbcreator_like.py`, que sigue bajo LGPL-3.0-or-later por derivar de
BloodHound-Tools (`cobertura/LICENSES/`); LGPL 3 es compatible con GPL 3.
