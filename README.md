# plugin-ldap – LDAP und Active Directory für Runnel

Offizielles [Runnel](https://github.com/runnelhq/runnel)-Plugin: sucht in Verzeichnissen (Active Directory, OpenLDAP
u. a.), prüft Anmeldungen, ändert Einträge und liest Einträge als Datensätze in Pipelines. Gebaut mit dem [Go-SDK](https://github.com/runnelhq/sdk-go) und
[go-ldap](https://github.com/go-ldap/ldap) (MIT).

| | |
|---|---|
| Namensraum | `ldap` |
| Connection-Typ | `ldap` (mit „Test connection“ im Editor) |
| Actions | `ldap.search`, `ldap.authenticate`, `ldap.add`, `ldap.modify`, `ldap.delete` |
| Transforms | `ldap.input` (Eingabe mit „Detect fields“) |
| Runnel | Actions und Connection-Typ ab S49c, `ldap.input` ab S50b |
| Lizenz | MIT; Lizenzen der Abhängigkeiten in `THIRD_PARTY_NOTICES` |

## Installieren

1. Archiv für das System von den [Releases](https://github.com/runnelhq/plugin-ldap/releases) laden
   (`runnel-plugin-ldap_<version>_windows_amd64.zip`) und die Prüfsumme mit `SHA256SUMS` vergleichen.
2. In den Ordner `plugins/` des Projekts entpacken, sodass `plugins/ldap/plugin.yaml` entsteht.
3. Freigeben und prüfen:

```bash
runnel plugins trust D:\flows --plugin ldap
runnel plugins D:\flows
```

## Connection

`connections/ad.yaml`:

```yaml
kind: Connection
apiVersion: runnel/v1
name: ad
type: ldap
with:
  url: ldaps://dc1.example.com          # oder ldap://dc1.example.com mit startTls: true
  bindDn: svc-runnel@example.com        # DN oder bei Active Directory user@domain; leer: anonym
  password: ${secret:ad-password}
  baseDn: DC=example,DC=com             # Start der Suchen, wenn eine Action keinen nennt
  # caFile: certs/example-ca.pem        # CA des Servers, falls der Rechner ihr nicht vertraut
  # serverName: dc1.example.com         # Name im Zertifikat, falls er vom Host in url abweicht
  # timeout: 30s                        # Verbindungsaufbau und je Anfrage
```

| Feld | Bedeutung |
|---|---|
| `url` | `ldaps://host[:636]` (TLS) oder `ldap://host[:389]` |
| `bindDn`, `password` | Anmeldung; `password` nur als Secret (`format: runnel-secret`). Ohne `bindDn` anonym |
| `startTls` | `ldap://`-Verbindung vor der Anmeldung auf TLS umstellen |
| `caFile`, `serverName` | eigene CA (PEM, relativ zum Projektordner) und Name im Zertifikat; TLS mindestens 1.2, Zertifikate werden immer geprüft |
| `allowUnencrypted` | Anmeldung mit Passwort über `ldap://` ohne TLS erlauben – das Passwort geht lesbar durchs Netz, nur für Tests |
| `timeout` | Standard `30s` |

**Sicherheit:** Ohne TLS lehnt das Plugin eine Anmeldung mit Passwort ab (`allowUnencrypted` nur für Tests). Ein leeres
Passwort wird nie gesendet, weil viele Server das als anonyme Anmeldung annehmen. „Test connection“ meldet sich nur an
und liest den Root DSE (Version des Servers); geschrieben wird nichts.

## Actions

Alle Actions nennen die Connection in `connection:`. Fehler des Servers erscheinen mit Bedeutung und Code, z. B.
`change uid=jdoe,…: no permission (LDAP result 50): …`.

### `ldap.search` – suchen

```yaml
- id: find
  type: ldap.search
  with:
    connection: ad
    baseDn: OU=Users,DC=example,DC=com    # leer: baseDn der Connection
    filter: (&(objectClass=user)(sAMAccountName={user}))
    filterValues:
      user: ${USER}                       # wird für LDAP maskiert
    attributes: [displayName, mail, memberOf]
    scope: sub                            # sub, one oder base
    sizeLimit: 1000                       # mehr Treffer: Fehler (höchstens 100000)
    pageSize: 500                         # Paged Results; 0: ohne
```

Ergebnis (`results.find.output`):

```json
{"count": 1, "entries": [{"dn": "CN=Jane Doe,OU=Users,DC=example,DC=com",
  "attributes": {"displayName": ["Jane Doe"], "mail": ["jdoe@example.com"], "memberOf": ["CN=Staff,…"]}}]}
```

- **Werte immer über `filterValues`**, nie direkt in `filter` (`(uid=${USER})`): Ein Wert wie `*)(uid=*` würde sonst den
  Filter ändern. `{name}` ohne Eintrag in `filterValues` ist ein Fehler.
- Jedes Attribut ist eine Liste (LDAP-Attribute können mehrere Werte haben), z. B.
  `{{ results.find.output.entries[0].attributes.mail[0] }}`.
- `objectGUID` und SIDs (`objectSid`, `tokenGroups`, `sidHistory`) kommen in der üblichen Schreibweise
  (`6f9619ff-8b86-…`, `S-1-5-21-…`), andere binäre Werte (z. B. `thumbnailPhoto`) als Base64.
- Mit `pageSize` liest das Plugin seitenweise; so liefert auch Active Directory mehr als 1000 Einträge.

### `ldap.authenticate` – Anmeldung prüfen

Sucht den Benutzer mit der Connection und meldet sich dann auf einer eigenen Verbindung als dieser Benutzer an.

```yaml
- id: login
  type: ldap.authenticate
  with:
    connection: ad
    username: ${USER}
    password: ${PASSWORD}
    attributes: [displayName, memberOf]   # nach erfolgreicher Anmeldung zurückgeben
    # userFilter: (|(uid={username})(sAMAccountName={username})(userPrincipalName={username}))
```

Ergebnis: `authenticated` (`true`/`false`), `dn`, `attributes`, `error`. Ein unbekannter Benutzer, ein falsches oder
leeres Passwort ergeben `authenticated: false` mit `error: invalid user or password` – ohne zu verraten, was davon
zutrifft. Findet `userFilter` mehrere Benutzer, scheitert die Action.

### `ldap.add`, `ldap.modify`, `ldap.delete` – ändern

```yaml
- id: create
  type: ldap.add
  with:
    connection: ldap-admin
    dn: uid=jdoe,ou=people,dc=example,dc=org
    attributes:
      objectClass: [inetOrgPerson]
      cn: Jane Doe                        # ein Wert oder eine Liste
      sn: Doe
      mail: [jdoe@example.org]

- id: change
  type: ldap.modify
  with:
    connection: ldap-admin
    dn: uid=jdoe,ou=people,dc=example,dc=org
    replace: { telephoneNumber: "+49 30 1234" }   # leere Liste entfernt das Attribut
    add: { mail: jane.doe@example.org }
    delete: { description: [] }                   # leere Liste: alle Werte

- id: remove
  type: ldap.delete
  with:
    connection: ldap-admin
    dn: uid=jdoe,ou=people,dc=example,dc=org
    ignoreMissing: true                   # fehlender Eintrag ist kein Fehler
```

Ergebnis: `dn` und `changed` (bei `ldap.delete` mit `ignoreMissing` `false`, wenn es den Eintrag nicht gab). Die
Reihenfolge in `ldap.modify` ist `delete`, `add`, `replace`, je Attribut alphabetisch.

### Transform `ldap.input` – Einträge als Datensätze

Eine Eingabe für Pipelines: liest die Einträge einer Suche seitenweise und gibt sie als Datensätze weiter. Weil die
Pipeline über Kredite bremst, liegt immer nur etwa eine Seite im Speicher – auch bei 100.000 Benutzern.

```yaml
transforms:
  - id: users
    type: ldap.input
    with:
      connection: ad
      baseDn: OU=Users,DC=example,DC=com
      filter: (&(objectClass=user)(department={dept}))
      filterValues: { dept: ${DEPARTMENT} }
      pageSize: 500                 # Standard; 0: ohne Paging
      # sizeLimit: 1000             # höchstens so viele Einträge; 0 (Standard): alle
      fields:
        - { name: login, from: sAMAccountName }
        - { name: dn }              # der DN des Eintrags
        - { name: mail }
        - { name: groups, from: memberOf, type: json }
        - { name: lastLogon, from: lastLogonTimestamp, type: datetime }
        - { name: guid, from: objectGUID }
  - id: write
    type: csv.output
    with: { path: users.csv }
links:
  - { from: users, to: write }
```

| Typ | Wert |
|---|---|
| `string` (Standard) | Text; mehrere Werte verbunden mit `separator` (Standard `; `); GUID/SID lesbar, andere binäre Werte Base64 |
| `int`, `bool` | erster Wert als Zahl bzw. `TRUE`/`FALSE` |
| `datetime` | LDAP-Zeit (`20261124103000Z`) oder Datei-Zeit von Active Directory (`pwdLastSet`, `lastLogonTimestamp`, `accountExpires`; `0` und „nie“ werden leer) |
| `binary` | erster Wert als Bytes (z. B. `thumbnailPhoto`) |
| `json` | Liste aller Werte |

- Fehlt ein Attribut, ist das Feld leer (`null`). Passt ein Wert nicht zum Typ, geht der Datensatz auf den
  **Fehler-Link** (`_error`, `_errorField`).
- Ohne `fields` kommen `dn` und alle Attribute des Eintrags als Text; die Felder hinter der Eingabe sind dann offen.
- **„Detect fields“** im Editor liest die ersten Einträge (mit allen Attributen) und schlägt je Attribut einen Typ vor:
  `json` bei mehreren Werten, `datetime` bei LDAP- und Datei-Zeiten, `int`, `bool`, `binary`, sonst `string`.
- `runnel validate` prüft über `transform.init` Filter, `scope` und `fields` (Namen doppelt, unbekannter Typ), ohne
  sich zu verbinden; die Felder sind danach für folgende Transforms bekannt.

Nicht enthalten (Ideen für später): Passwörter in Active Directory setzen (`unicodePwd`), Einträge umbenennen oder
verschieben (`modifyDN`), Kerberos/NTLM-Anmeldung, ein Transform zum Nachschlagen je Datensatz (`ldap.lookup`).

## Entwickeln

| Zweck | Befehl |
|---|---|
| Bauen | `make build` → `bin/ldap` |
| Tests (mit Race-Detector) | `make test` – die Tests mit Server starten ein eigenes OpenLDAP (`slapd`, unter Debian/Ubuntu `apt-get install slapd`) auf freien Ports von `127.0.0.1` mit TLS; ohne `slapd` werden sie übersprungen |
| Tests gegen Runnel | `make runnel-test RUNNEL_BIN=../runnel/bin/runnel` |
| Lint (golangci-lint v2.15.0) | `make lint` (ohne passendes golangci-lint: `make bin/tools/golangci-lint lint GOLANGCI_LINT=bin/tools/golangci-lint`) |
| Fuzzing | `make fuzz FUZZTIME=1m` |
| Benchmark | `make bench` |
| Release-Archive | `make dist` → `dist/*.zip`, `dist/SHA256SUMS` |
| Release veröffentlichen | `version` in `plugin.yaml` und `main.go` erhöhen, mergen, dann Tag `v<version>` pushen oder den Workflow „Release“ auf `main` mit der Version starten; er prüft die Version, testet, baut die Archive mit Herkunftsnachweis und legt das GitHub-Release an |

Unter Ubuntu verhindert das AppArmor-Profil von `slapd` den Zugriff auf temporäre Ordner; die CI schaltet es ab. Gegen
ein echtes Active Directory gibt es keine automatischen Tests – dafür einmal von Hand (Suche mit Paging,
`objectGUID`/`objectSid`, Anmeldung mit `user@domain`).

Die Version in `plugin.yaml` und `version` in `main.go` passen zum Tag (`v0.1.0`); ein Test prüft das. Änderungen
stehen in [CHANGELOG.md](CHANGELOG.md).
