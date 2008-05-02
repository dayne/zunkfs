cd ~
TARGET_OPTIONS="use local"
for I in $TARGET_OPTIONS; do
  if [ -d $I ] ; then
    TARGET=$I
  fi
done

if [ ! -d $TARGET ] ; then
  echo "I couldn't find a TARGET in ~ (options considered: $TARGET_OPTIONS)"
  exit
fi

cd $TARGET

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

echo "set the following fun in your ~/.bashrc (or whatever) file (if it isn't already):"
echo 'LD_LIBRARY_PATH='$HOME/$TARGET:'$LD_LIBRARY_PATH'
