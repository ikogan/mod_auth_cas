#!/bin/bash
set -e

cd /data

# Create the build scripts
libtoolize
autoreconf --install
automake --add-missing

# Configure the package and create a source tarball
./configure --with-apxs=/usr/sbin/apxs
make dist

# Prepare to build the RPM
cp -Rv redhat/* ~/rpmbuild/SOURCES
mv -v mod_auth_cas-*.*gz ~/rpmbuild/SOURCES
chown -Rv root.root ~/rpmbuild

# Build the RPM
rpmbuild -ba ~/rpmbuild/SOURCES/mod_auth_cas.spec

# Copy the RPM back out to of the container
mkdir -p /data/dist/{RPMS,SRPMS}
cp -rv ~/rpmbuild/RPMS/* /data/dist/RPMS
cp -rv ~/rpmbuild/SRPMS/* /data/dist/SRPMS
