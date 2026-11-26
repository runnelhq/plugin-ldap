# Änderungen

## v0.1.0 (2026-11-26)

- Erste Version: Connection-Typ `ldap` (ldaps, StartTLS, eigene CA, Test im Editor), Actions `ldap.search` (Paged
  Results, maskierte Filterwerte, GUID/SID), `ldap.authenticate`, `ldap.add`, `ldap.modify`, `ldap.delete`.
- Transform `ldap.input`: Einträge seitenweise als Datensätze, Typen `string`, `int`, `bool`, `datetime` (auch
  Datei-Zeiten von Active Directory), `binary`, `json`, Fehler-Link; `transform.init` und „Detect fields“.
- Die Actions haben keine Kategorie mehr und stehen in Runnel (ab runnel#236) in der eigenen Gruppe
  „Plugin: ldap“ der Palette. `ldap.input` bleibt unter den Eingaben.
- Referenz für alle Bausteine (SDK `v0.3.0`, Runnel ab E15b): Ergebnis der Actions mit Pfad und Typ, Felder und
  Datensätze von `ldap.input`, wann sie scheitern und ihre Grenzen (`sizeLimit`, `pageSize`, `timeout`); zu sehen im
  Katalog des Projekts (`runnel serve`, `/api/v1/catalog`) und in der Hilfe des Editors. Ein Test hält die Angaben mit den Ergebnis-Structs
  gleich.
- Release-Archive für Windows und Linux (x64), wie Runnel selbst.
