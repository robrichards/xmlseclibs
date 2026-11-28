#!/usr/bin/env bash
# Installs this checkout as a dependency of a separate Composer project (path
# repository, copied like a real install, no vendor/ or tests/) and checks that
# the classes work through vendor/autoload.php and through a direct include of
# vendor/robrichards/xmlseclibs/xmlseclibs.php, in default and legacy mode.
#
# Usage: tests/consumer/run.sh [git-ref]   (default: HEAD, committed files only)
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
ref="${1:-HEAD}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir "$work/pkg" "$work/consumer"
git -C "$root" archive "$ref" | tar -x -C "$work/pkg"
cat > "$work/consumer/composer.json" <<JSON
{
  "name": "example/consumer",
  "repositories": [{ "type": "path", "url": "../pkg", "options": { "symlink": false, "versions": { "robrichards/xmlseclibs": "5.0.0" } } }],
  "require": { "robrichards/xmlseclibs": "5.0.0" }
}
JSON
cp "$root/tests/consumer/check.php" "$work/consumer/check.php"
cd "$work/consumer"
composer install --no-interaction --quiet

status=0
for legacy in "" legacy; do
  for mode in autoload direct direct-after-autoload; do
    php check.php "$mode" $legacy || status=1
  done
done
exit $status
