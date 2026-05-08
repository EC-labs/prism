Install dependencies:
```
chartPath="$(nix build --print-out-paths .#prism-chart)"
helm install cert-manager --create-namespace -n cert-manager "$chartPath/prism-chart/charts/cert-manager" --set crds.enabled=true
helm install clickhouse-operator --create-namespace -n clickhouse-operator "$chartPath/prism-chart/charts/clickhouse-operator-helm"
```

Install prism (replace `<namespace>` and `<podSubstring>`):
```
helm install prism \
    -n prism --create-namespace \
    "$(nix build --print-out-paths .#prism-chart)/prism-chart" \
    --set prism.bootstrap.namespace=<namespace> \
    --set prism.bootstrap.podSubstring=<podSubstring>
```

Point to private repository and prism tag (replace `<namespace>` and `<podSubstring>`):
```
helm install prism \
    -n prism --create-namespace \
    "$(nix build --print-out-paths .#prism-chart)/prism-chart" \
    --set prism.imageRepository="federer.ad.dlandau.nl:30002/library/prism-agent" \
    --set prism.tag=b2ac86f-dirty \
    --set prism.bootstrap.namespace=<namespace> \
    --set prism.bootstrap.podSubstring=<podSubstring>
```

Installing prism will also install a clickhouse cluster with 2 shards (1 replica each). The number of clickhouse shards and replicas are also configurable. By default, the password for clickhouse's `default` user is `secret-password`, and the password for the `reader` user is `secret_password`. 

Check out the `values.yaml` file in the prism-chart to see additional configuration values.
