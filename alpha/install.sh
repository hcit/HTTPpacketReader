#INSTALLING LIBNET
cd libnet-1.1.6
./configure
make
echo "sudo make install"
sudo make install
cd ..
#INSTALLING GLIBC
# cd glibc
# ./configure
# make
# echo "sudo make install"
# sudo make install
#INSTALLING LIBNIDS
cd libnids-1.24
./configure
make
#sudo make install
cd ..
make hope