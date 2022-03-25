#!/bin/bash
set -eu

update_label() {
# $1 is a username
USER=$1
# $2 is a cutoff date; use $(date +%Y-%m-%d) for now
DATE=$2

  gh api -X GET search/issues -f q="repo:aws/s2n-tls is:open -label:s2n-core author:${USER} created:<${DATE}" > ${USER}.json
  jq  -c -r '.items|.[]|.number' $USER.json > ${USER}_ISSUES.log
  if [ $(cat ${USER}_ISSUES.log|wc -l) -eq 0 ]; then
    echo "No issues for ${USER}"
    return
  fi
  echo "Found $(cat ${USER}_ISSUES.log|wc -l) issues for $USER, continue?"
  read
  for issue in $(cat ${USER}_ISSUES.log); do
    echo "Updating $issue"
    echo '["s2n-core"]'| gh api --silent -X POST repos/aws/s2n-tls/issues/$issue/labels --input -
  done
  echo "Done with $USER"
}

internal="toidiu
zaherd
NLMalloy
ttjsu-aws
rday
agray256
tawdry-audrey
salusasecondus
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

for USER in ${internal}; do
  update_label ${USER} $(date +%Y-%m-%d)
done

for USER in ${maint}; do
  update_label ${USER} 2019-10-23
done
