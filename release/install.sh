sudo apt-get install -y libpcap-dev libglib2.0-dev libnet1-dev
tar -xzvf libnids-1.24.tar.gz
#rm libnids-1.24.tar.gz
cd libnids-1.24
./configure
make
sudo make install
cd ..
unzip LectorPaquetesHash.zip
#rm LectorPaquetesHash.zip
rm -R libnids-1.24
make hope