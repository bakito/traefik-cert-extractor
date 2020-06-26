#!/bin/sh -e

set -e

if [[ $# -ne 1 ]] ; then
    echo 'please use version as argument'
    exit 1
fi

CHANGED=$(git diff-index --name-only HEAD --)
if [[ ! -z $CHANGED ]]; then
    echo "Please commit your local changes first"
    exit 1
fi

RELEASE=${1}

GO_VERSION=$(cat go.mod | grep -a "^go.*" | awk '{print $2}')

sed -i "s/golang:.*/golang:${GO_VERSION} as builder/" build/Dockerfile

git add .
git diff-index --quiet HEAD || git commit -m "prepare release ${RELEASE}"
git push

echo "Create Release"
curl --header "Content-Type: application/json" \
  --header "Authorization: token ${GITHUB_TOKEN}" \
  --request POST \
  --data "{
  \"tag_name\": \"v${RELEASE}\",
  \"name\": \"v${RELEASE}\",
  \"draft\": false,
  \"prerelease\": false
}" https://api.github.com/repos/bakito/traefik-cert-extractor/releases
