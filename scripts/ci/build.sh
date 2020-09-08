#!/bin/bash

set -e

DIST="global"
VERSION=${VERSION:-dev}


rm -fr dist
mkdir -p dist/

for d in ${DIST}; do

    # Build required values
    echo "version: ${VERSION}" > ${d}/nse/FEED_INFO.yaml
    PACKAGE=nse-${d}-feed-${VERSION}.tar.gz

    # Packaging
    tar -czf dist/${PACKAGE} -C ${d}/nse --transform "s,.,./nse/${d}," .

    # Cleanup
    rm ${d}/nse/FEED_INFO.yaml

done

echo "All done, packages were build."
ls -l dist/
