#!/bin/bash
# Build and push the multi-platform image, then package and push the Helm chart, to an OCI registry.
# The image tag is the chart's appVersion; the chart is pushed under its own version.
#
#   REGISTRY=oci.example.com ./deploy-assets-oci.sh
#
#   REGISTRY    registry to push to (required)
#   IMAGE_REPO  path of the image in the registry (default library/spitter)
#   CHART_REPO  path of the chart in the registry (default helm/spitter)
#
# Log in to the registry first, with both "docker login" and "helm registry login".
set -euo pipefail
cd "$(dirname "$0")"

: "${REGISTRY:?Set REGISTRY to the registry to push to, e.g. REGISTRY=oci.example.com $0}"
IMAGE_REPO="${IMAGE_REPO:-library/spitter}"
CHART_REPO="${CHART_REPO:-helm/spitter}"

chart_dir="helm/spitter"
chart_name="$(yq -r '.name' "$chart_dir/Chart.yaml")"
chart_ver="$(yq -r '.version' "$chart_dir/Chart.yaml")"
app_ver="$(yq -r '.appVersion' "$chart_dir/Chart.yaml")"

# "helm push" takes the location the chart goes under and adds the chart's own name to it
if [ "${CHART_REPO##*/}" != "$chart_name" ]; then
    echo "CHART_REPO must end in the chart's name, $chart_name; got $CHART_REPO" >&2
    exit 1
fi
chart_parent="$REGISTRY"
if [ "$CHART_REPO" != "$chart_name" ]; then
    chart_parent="$REGISTRY/${CHART_REPO%/*}"
fi

image="$REGISTRY/$IMAGE_REPO"
echo "Application version: $app_ver -> $image:$app_ver"
echo "Chart version:       $chart_ver -> oci://$chart_parent/$chart_name:$chart_ver"

docker build --platform linux/amd64,linux/arm64 --build-arg VERSION="$app_ver" \
    -t "$image:$app_ver" -f Dockerfile .
docker push "$image:$app_ver"
docker tag "$image:$app_ver" "$image:latest"
docker push "$image:latest"

package_dir="$(mktemp -d)"
trap 'rm -rf "$package_dir"' EXIT
helm package "$chart_dir" -d "$package_dir"
helm push "$package_dir/$chart_name-$chart_ver.tgz" "oci://$chart_parent"

# The chart's default image is docker.io/spirilis/spitter, so an install from this registry has to name the image
cat <<DONE

Pushed.  To install from this registry:

  helm upgrade --install spitter oci://$chart_parent/$chart_name --version $chart_ver \\
    --set image.registry=$REGISTRY --set image.repository=$IMAGE_REPO -f my-values.yaml
DONE
