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
  if [ -d ${realpath}/src/$1 ]; then
    export GOPATH=${realpath}
    go fmt $1 || exit -1
    go get -d -v $1 || exit -1
    go install -ldflags "-w -s" $1 || exit -1
    echo "build done"
  fi
fi
