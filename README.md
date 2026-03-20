# trivy-plugin-govulncheck

# What it does
Runs govulncheck against a gobinary artefacts in Trivy Scans

# Installation
```
trivy install github.com/quentinkhoo/trivy-plugin-govulncheck
```

# Usage
```
trivy govulncheck --image grafana/beyla:2.7.11
trivy govulncheck --image grafana/beyla:2.7.11 --severity CRITICAL,HIGH --ignore-unfixed
```