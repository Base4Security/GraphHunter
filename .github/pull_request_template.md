<!-- markdownlint-disable MD041 -->
## ¿Qué cambia?

<!-- Resumen en 1-3 oraciones de lo que hace este PR. -->

## ¿Por qué?

<!-- Motivación del cambio. Si aplica, referencia la issue (#123), la spec
(`docs/specs/...`), o el RFC correspondiente. -->

## Tipo de cambio

- [ ] feat (nueva funcionalidad)
- [ ] fix (corrección de bug)
- [ ] docs (solo documentación)
- [ ] chore (mantenimiento, build, deps)
- [ ] refactor (cambio interno sin alterar comportamiento)
- [ ] perf (mejora de rendimiento)
- [ ] test (agregar o ajustar tests)
- [ ] ci (cambios en pipelines / workflows)
- [ ] breaking (cambio incompatible con la API/CLI/formato actual)

## Checklist

- [ ] Tests pasan (`cargo test` para Rust, `npm test` para Tauri/MCP)
- [ ] CHANGELOG.md actualizado si aplica
- [ ] Docs actualizadas (README, CONTRIBUTING)
- [ ] Sin secrets en el diff (corrí `gitleaks git --staged`)
- [ ] Sin datos reales en tests, fixtures ni docs: ni de clientes ni de personas (CUIL, nombres, domicilios, cuentas, IPs públicas)
- [ ] Puedo explicar cada línea del diff, la haya escrito yo o la IA
- [ ] Si toca autenticación, credenciales de SIEM, parsers o carga de sesiones: lo revisé línea por línea
- [ ] Si agrega o actualiza una dependencia: lockfile actualizado y sin vulnerabilidades conocidas
- [ ] Si cambia el consumo de IA (más llamadas, modelo, contexto): impacto estimado en la descripción
- [ ] PR linkea issue o spec si aplica

## Cómo probarlo

<!-- Pasos reproducibles para el reviewer:
1. `git checkout <branch>`
2. `cargo build --release`
3. `./target/release/graphhunter ...`
4. Verificar que ...
-->

## Screenshots / output

<!-- Si aplica, pegar screenshots, logs o salida relevante. Si no aplica,
borrar esta sección. -->
