---
operational_runbook:
  contract: operational-runbook.v1
  id: heim-pc.asr.local-transcription
  status: active
  title: Lokale Audio-Transkription über die kanonische ASR-Route
  applies_to:
    operations: [audio.transcribe, transcribe, transcription, asr]
    platforms: [linux, heim-pc]
    components: [asr, audio]
  symptoms: [transcription-route-unknown, canonical-asr-runtime-missing, duplicated-model-cache, per-request-venv]
  evidence_refs: [architecture/asr-engine.md, manifest/operator-entry.v1.json, manifest/asr-engine-policy.v1.json, scripts/asr_engine.py]
  verified_against:
    - repository: heimgewebe/heim-pc
      commit: ac514e37ef24b594aa51a7c2157ae94f4ab94ace
    - route: audio.transcribe
      readiness: doctor
      setup: shared-cache-only
  does_not_establish: [current_state, root_cause, mutation_permission, retry_permission, task_completion, routing_authority, policy_authority, merge_readiness, deployment_authority]
  known_bad_paths: [per-request-pip-install, per-request-virtualenv, per-request-model-cache, silent-cloud-fallback, consumer-engine-pinning]
  rollback:
    principle: Do not delete or replace the shared ASR cache as an automatic recovery action.
    action: Re-read the capability locator and policy, run doctor, and repair only the explicitly failed canonical component.
---

# Lokale Audio-Transkription

## Zweck

Für lokale Audio-Transkription auf dem Heim-PC existiert bereits eine kanonische, lokale ASR-Route. Neue Aufträge sollen diese Route **wiederverwenden**, nicht pro Audiodatei eine neue Whisper-Installation, virtuelle Umgebung oder einen eigenen Modellcache aufbauen.

Dieses Runbook ist nur operative Guidance. Es ersetzt weder frische Runtime-Prüfung noch die ASR-Policy und erteilt keine Mutations-, Retry-, Kosten- oder Abschlussautorität.

## 1. Native Oberfläche vor Host-Locator prüfen

Vor dem host-local Schritt zuerst eine bereits veröffentlichte native typed Grabowski-Oberfläche verwenden, wenn sie den Auftrag erfüllt. Nur wenn keine solche Oberfläche passt, den installierten Maschinenvertrag über die host-local Capability-Auflösung lesen. Ein `blocked` ist kein Miss und darf nicht durch einen Ersatzpfad umgangen werden. Nur ein explizites `not_found` darf zu einer bereits deklarierten Spezialroute weiterführen:

`grabowski_host_capability_resolve(intent="audio.transcribe")`

Erwartete stabile Semantik der Auflösung:

- Capability: `audioTranscription`
- Autorität: `heim_pc_asr_open_engine`
- kanonischer Einstieg: `python3 ${HOME}/repos/heim-pc/scripts/asr_engine.py`
- Default-Operation: `transcribe`
- Readiness-Operation: `doctor`
- Engine-Pinning durch den Consumer: nicht erlaubt
- Cloud-/Metered-Autorität durch den Locator: nicht erteilt

Wenn die Capability nicht eindeutig auflösbar ist oder die installierte Projektion vom kanonischen Vertrag abweicht, **nicht** durch eine ad-hoc-Installation ausweichen. Erst die Entrée-/Projektionsdrift klären.

## 2. Readiness vor Setup

Vor jeder Installation den kanonischen lokalen Zustand prüfen:

`python3 ${HOME}/repos/heim-pc/scripts/asr_engine.py doctor`

`doctor` ist ein Readiness-Check und löst ohne `--engine` den aktuellen `default_engine` aus der ASR-Policy zur Ausführungszeit auf. Fehlende Runtime oder fehlender Modellcache sind ein belegter Setup-Grund; ein bloß unbekannter Zustand ist keiner. Den Default nicht im Consumer hardcoden.

## 3. Nur den gemeinsamen Setup-Pfad verwenden

Nur wenn `doctor` konkret fehlende lokale Komponenten meldet:

`python3 ${HOME}/repos/heim-pc/scripts/asr_engine.py setup --engine <aktueller-default_engine>`

`setup` verlangt technisch einen Engine-Namen. Diesen Wert unmittelbar vorher aus dem zur Ausführungszeit gelesenen Policy-Feld `default_engine` übernehmen; das ist Parameterübergabe, kein dauerhafter Consumer-Pin.

Der kanonische Setup-Pfad verwendet den gemeinsamen Runtime-/Modellcache unter:

`~/.local/cache/heim-pc/asr-open-engine/`

Nicht verwenden:

- eine `.venv` pro Auftrag;
- `pip install` innerhalb eines Projekt- oder Transkriptionsordners;
- einen separaten Hugging-Face-/Whisper-Modellcache pro Auftrag;
- einen stillen Wechsel auf Cloud- oder Metered-ASR;
- einen Consumer-seitig gepinnten Engine-Pfad als neue lokale Wahrheit.

## 4. Transkribieren

Für die policy-gesteuerte lokale Route:

`python3 ${HOME}/repos/heim-pc/scripts/asr_engine.py transcribe --audio /pfad/zur/audio-datei`

Für einen strukturierten Routing-Nachweis:

`python3 ${HOME}/repos/heim-pc/scripts/asr_engine.py route --audio /pfad/zur/audio-datei --json`

Die Route liest die aktuelle ASR-Policy zur Ausführungszeit. Ein vorhandener Cache oder dieses Runbook beweist allein nicht, dass die Runtime jetzt gesund ist.

## 5. Verifikation

Nach Setup oder bei einem vermuteten Runtimeproblem mindestens:

1. `doctor` erneut ausführen;
2. prüfen, dass Runtime und Modellcache als vorhanden/gesund gelesen werden;
3. einen kurzen repräsentativen Audioausschnitt über die kanonische Route transkribieren;
4. im strukturierten Ergebnis prüfen, dass `provider=local` und die erwartete Local-first-Strategie verwendet wurde;
5. keine Transkriptinhalte in Diagnose- oder Operatorlogs schreiben, wenn dafür kein fachlicher Bedarf besteht.

## Bekannte Fehlpfade

### Ad-hoc-Umgebung trotz vorhandener Capability

Symptom: Ein Auftrag beginnt mit Werkzeugsuche, `pip install` oder einer neuen `.venv`, obwohl `audio.transcribe` bereits über den Operator-Entry-Vertrag auflösbar ist.

Korrektur: Capability auflösen → `doctor` → nur bei belegtem Fehlen `setup` → kanonische Route benutzen.

### Gemeinsame Route vorhanden, Runtime aber noch nicht eingerichtet

Die Existenz von Architektur, Locator und Script beweist nicht, dass Runtime und Modellcache bereits installiert sind. In diesem Fall ist ein **einmaliges kanonisches Setup** korrekt; eine private Auftragsumgebung ist es nicht.

### Cloud als vermeintlicher Fallback

Unklare oder fehlende lokale Readiness erteilt keine Cloud-/Kostenfreigabe. Cloud- oder Metered-Inferenz benötigt weiterhin die dafür vorgesehene explizite Autorität.

## Grenzen / Non-Claims

Dieses Runbook etabliert ausdrücklich nicht:

- aktuellen Runtimezustand;
- Root Cause eines Fehlers;
- Mutations- oder Retry-Erlaubnis;
- Task-Abschluss;
- Routing- oder Policy-Autorität;
- Merge- oder Deployment-Reife.

Stand der Erstverifikation: 2026-09-07.
