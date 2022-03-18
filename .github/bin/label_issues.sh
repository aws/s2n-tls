#!/bin/bash
set -eu

update_label() {
# $1 is a \n separated list of users
# $2 is a cutoff date; use $(date +%Y-%m-%d) for now

for USER in $1; do
  echo "Looking up issues for $USER, continue?"
  read 
  gh api -X GET search/issues -f q="repo:aws/s2n-tls is:open -label:s2n-core author:$USER created:<$2" > $USER.json
  jq  -c -r '.items|.[]|.number' $USER.json > ${USER}_ISSUES.log
  for issue in $(cat ${USER}_ISSUES.log); do
     echo "Updating $issue"
     echo '["s2n-core"]'| gh api --silent -X POST repos/$OWNER/$REPO/issues/$issue/labels --input -
  done
  echo "Done with $USER"
done
}

internal="toidiu
dougch
lrstewart
goatgoose
camshaft
maddeleine
WesleyRosenblum"

maint="colmmacc
alexw91
baldwinmatt
soco
alexeblee"

update $internal $(date +%Y-%m-%d)
update_label $maint 2019-10-23
