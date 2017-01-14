# # install unzip
# wget http://launchpadlibrarian.net/40403522/unzip_6.0-1build1_amd64.deb
# dpkg -i unzip_6.0-1build1_amd64.deb
# # get and unzip Repo
# wget https://github.com/codelion/pathgrind/archive/master.zip
# unzip master.zip -d .
# # install m4
# wget http://launchpadlibrarian.net/35791102/m4_1.4.13-3_amd64.deb
# dpkg -i m4_1.4.13-3_amd64.deb
# # install autoconf
# wget http://launchpadlibrarian.net/37077080/autoconf_2.65-3ubuntu1_all.deb
# dpkg -i autoconf_2.65-3ubuntu1_all.deb
# # install gawk
# wget http://launchpadlibrarian.net/36679708/gawk_3.1.6.dfsg-4build1_amd64.deb
# dpkg -i gawk_3.1.6.dfsg-4build1_amd64.deb
# # install ia32-libs
# libc6 (= 2.11.1-0ubuntu7)
# wget http://launchpadlibrarian.net/45027772/libc6-i386_2.11.1-0ubuntu7_amd64.deb
# dpkg -i libc6-i386_2.11.1-0ubuntu7_amd64.deb
# wget http://launchpadlibrarian.net/96032927/lib32gcc1_4.4.3-4ubuntu5.1_amd64.deb
# dpkg -i lib32gcc1_4.4.3-4ubuntu5.1_amd64.deb
# libc6-i386 (>= 2.3.6-2)
# lib32z1
# lib32stdc++6
# lib32asound2
# lib32bz2-1.0
# lib32ncurses5
# lib32v4l-0

# wget http://launchpadlibrarian.net/69938672/ia32-libs_2.7ubuntu26.1_amd64.deb
# dpkg -i ia32-libs_2.7ubuntu26.1_amd64.deb

# write new sourcelist
cat <<EOF > /etc/apt/sources.list
deb http://ftp.hosteurope.de/mirror/old-releases.ubuntu.com/ubuntu/ lucid main restricted multiverse universe
deb http://ftp.hosteurope.de/mirror/old-releases.ubuntu.com/ubuntu/ lucid-security main restricted universe multiverse
deb http://ftp.hosteurope.de/mirror/old-releases.ubuntu.com/ubuntu/ lucid-updates main restricted universe multiverse

deb http://old-releases.ubuntu.com/ubuntu/ lucid main multiverse universe
deb http://old-releases.ubuntu.com/ubuntu/ lucid-security main restricted universe multiverse
EOF

# install dependeciesvag
apt-get update
apt-get install -y unzip
apt-get install -y automake
apt-get install -y autoconf
apt-get install -y gawk
# apt-get install -y ia32-libs

# get and install fuzzgrind
cd /home/vagrant/
wget https://github.com/codelion/pathgrind/archive/master.zip
unzip master.zip -d .
cd pathgrind-master
./install.sh