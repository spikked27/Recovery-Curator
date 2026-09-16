#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template_dir="/boot/config/plugins/dockerMan/templates-user"
template_target="${template_dir}/my-recovery-curator.xml"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker was not found. Run this script from the Unraid terminal."
  exit 1
fi

docker build --pull -t recovery-curator:local "${script_dir}"
mkdir -p "${template_dir}"
cp "${script_dir}/unraid-template.xml" "${template_target}"

echo "Recovery Curator image built and Unraid template installed."
echo "In the Unraid web UI, open Docker > Add Container and select Recovery-Curator."
echo "Confirm the Recovered Source path before applying the template."

