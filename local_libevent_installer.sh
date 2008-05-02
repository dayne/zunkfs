#!/bin/bash

if [ ! -f  local_libevent_installer.sh ]; then
  echo "You should be running this from the zunkfs directory so I can create the handy file needed for the Makefile"
  exit
fi

pushd .
cd ~
TARGET_OPTIONS="usr local"
TARGET='failed'
for I in $TARGET_OPTIONS; do
  if [ -d ./$I ] ; then
    TARGET=$I
  fi
done

if [ $TARGET == 'failed' ] ; then
  echo "I couldn't find a TARGET in ~ (options considered: $TARGET_OPTIONS)"
  exit
fi

echo "using $HOME/$TARGET"
cd $TARGET
sleep 1

if [ ! -d src ] ; then
  mkdir src
fi

cd src

if [ ! -f libevent-1.4.3-stable.tar.gz ] ; then
  wget --quiet http://monkey.org/~provos/libevent-1.4.3-stable.tar.gz
fi

if [ ! -d libevent-1.4.3-stable/ ] ; then
  tar xvfz libevent-1.4.3-stable.tar.gz
fi

cd libevent-1.4.3-stable/
make clean
./configure --prefix=$HOME/$TARGET/
make
make install

popd

echo 
echo "-----------------------------------------"
echo "Go and set the following environment variable somewhere (.bashrc perhaps)"
echo "export LIBEVENT_PREFIX=$HOME/$TARGET"
