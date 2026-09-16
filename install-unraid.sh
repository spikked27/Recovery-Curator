#!/bin/bash
set -euo pipefail

template_dir="/boot/config/plugins/dockerMan/templates-user"
template_target="${template_dir}/my-recovery-curator.xml"
template_url="https://raw.githubusercontent.com/spikked27/Recovery-Curator/main/unraid-template.xml"

mkdir -p "${template_dir}"
curl -fsSL "${template_url}" -o "${template_target}"

echo "Recovery Curator Unraid template installed."
echo "In the Unraid web UI, open Docker > Add Container and select Recovery-Curator."
echo "Confirm the Recovered Source path before applying the template."
