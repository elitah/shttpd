#/bin/sh

realpath=`realpath -L $0`

if [ -z ${realpath} ]; then
  exit
fi

realpath=`dirname ${realpath}`

if [ -z ${realpath} ]; then
  exit
fi

if [ ! -z $1 ]; then
  if [ -d src/$1 ]; then
    export GOPATH=${realpath}
    go install $1
  fi
fi

