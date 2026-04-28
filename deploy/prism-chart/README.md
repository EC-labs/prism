Install dependencies:
```
chartPath="$(nix build --print-out-paths .#prism-chart)"
helm install cert-manager --create-namespace -n cert-manager "$chartPath/prism-chart/charts/cert-manager" --set crds.enabled=true
helm install clickhouse-operator --create-namespace -n clickhouse-operator "$chartPath/prism-chart/charts/clickhouse-operator-helm"
```

Install prism:
```
helm install prism -n prism --create-namespace "$(nix build --print-out-paths .#prism-chart)/prism-chart"
```
