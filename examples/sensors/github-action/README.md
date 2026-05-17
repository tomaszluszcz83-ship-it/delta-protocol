# DELTA GitHub Action Sensor Example

The repository workflow `.github/workflows/delta-sensor.yml` generates a dirty DELTA sensor record.

It runs on:

- `workflow_dispatch`
- pushes to `main`
- pushes to `sensors/**`
- pull requests into `main`

The generated artifact is named:

```text
delta-sensor-record
```

It contains:

```text
delta-record.json
delta-sensor-output.log
delta-sensor-error.log
delta-replay.sh
delta-sensor-summary.md
```

This is the first sensor-layer prototype.

It is not the final Delta Record RFC.
