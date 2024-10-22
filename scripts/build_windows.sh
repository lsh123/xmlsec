#!/bin/bash
#
# MUST BE RUN FROM x64 Native Tools Command Prompt
#
# $ bash build_windows.sh
#
libxml2_version="2.13.4"
libxslt_version="1.1.42"
openssl_version="3.4.0"
xmlsec_version="1.3.7-rc1"

pwd=`pwd`
script_dir=`dirname $0`
work_dir="c:\\local\\dev"
distro_dir="c:\\local\\distro"
libxml2_output_dir="${distro_dir}\libxml2"
libxslt_output_dir="${distro_dir}\libxslt"
openssl_output_dir="${distro_dir}\openssl"
xmlsec_output_dir="${distro_dir}\xmlsec"

zip_folders_and_files="libxml2 libxslt openssl xmlsec README.md"
zip_output_file="${distro_dir}\\xmlsec1-${xmlsec_version}-win64.zip"

PERL_PATH="C:\\Strawberry\\perl\\bin"
LOG_FILE="C:\\temp\\build-windows.log"

function build_libxml2 {
  # check if already built
  full_name="libxml2-v${libxml2_version}"
  full_url="https://gitlab.gnome.org/GNOME/libxml2/-/archive/v${libxml2_version}/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name}" -a -d "${libxml2_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Folder \"${work_dir}\\${full_name}\" and/or \"${libxml2_output_dir}\" are missing, rebuilding ${full_name}"
  fi

  # build it!
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name}" "${libxml2_output_dir}"

  if [ ! -f "${full_name}.tar.gz" ] ; then
    echo "*** Downloading ${full_name}..."
    wget "${full_url}"
  else
    echo "*** File \"${full_name}.tar.gz\" already exists"
  fi

  echo "*** Extracting \"${full_name}\" archive..."
  tar xvfz "${full_name}.tar.gz" 2>> "${LOG_FILE}"

  echo "*** Configuring \"${full_name}\" ..."
  cd "${full_name}\win32"
  cscript configure.js iconv=no zlib=no cruntime=/MD prefix="${libxml2_output_dir}" >> "${LOG_FILE}"

  echo "*** Building \"${full_name}\" ..."
  nmake >> "${LOG_FILE}"

  echo "*** Installing \"${full_name}\" ..."
  nmake install >> "${LOG_FILE}"

  echo "*** Done with \"${full_name}\"!!!"
  return 0
}

function build_libxslt {
  # check if already built
  full_name="libxslt-v${libxslt_version}"
  full_url="https://gitlab.gnome.org/GNOME/libxslt/-/archive/v${libxslt_version}/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name}" -a -d "${libxslt_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Folder \"${work_dir}\\${full_name}\" and/or \"${libxslt_output_dir}\" are missing, rebuilding ${full_name}"
  fi

  # build it!
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name}" "${libxslt_output_dir}"

  if [ ! -f "${full_name}.tar.gz" ] ; then
    echo "*** Downloading ${full_name}..."
    wget "${full_url}"
  else
    echo "*** File \"${full_name}.tar.gz\" already exists"
  fi

  echo "*** Extracting \"${full_name}\" archive..."
  tar xvfz "${full_name}.tar.gz" 2>> "${LOG_FILE}"

  echo "*** Configuring \"${full_name}\" ..."
  cd "${full_name}\win32"
  cscript configure.js iconv=no zlib=no cruntime=/MD prefix="${libxslt_output_dir}" include="${libxml2_output_dir}\include\libxml2" lib="${libxml2_output_dir}\lib"

  echo "*** Building \"${full_name}\" ..."
  nmake >> "${LOG_FILE}"

  echo "*** Installing \"${full_name}\" ..."
  nmake install >> "${LOG_FILE}"

  echo "*** Done with \"${full_name}\"!!!"
  return 0
}

function build_openssl {
  # check if already built
  full_name="openssl-${openssl_version}"
  full_url="https://github.com/openssl/openssl/releases/download/openssl-${openssl_version}/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name}" -a -d "${openssl_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Folder \"${work_dir}\\${full_name}\" and/or \"${openssl_output_dir}\" are missing, rebuilding ${full_name}"
  fi

  # build it!
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name}" "${openssl_output_dir}"

  if [ ! -f "${full_name}.tar.gz" ] ; then
    echo "*** Downloading ${full_name}..."
    wget "${full_url}"
  else
    echo "*** File \"${full_name}.tar.gz\" already exists"
  fi

  echo "*** Extracting \"${full_name}\" archive..."
  tar xvfz "${full_name}.tar.gz" 2>> "${LOG_FILE}"

  echo "*** Configuring \"${full_name}\" ..."
  OLD_PATH="$PATH"
  PATH="$PATH;$PERL_PATH"
  cd "${full_name}"
  perl Configure no-unit-test --prefix="${openssl_output_dir}" --release VC-WIN64A
  PATH="$OLD_PATH"

  echo "*** Building \"${full_name}\" ..."
  nmake >> "${LOG_FILE}"

  echo "*** Installing \"${full_name}\" ..."
  nmake install_sw >> "${LOG_FILE}"

  echo "*** Done with \"${full_name}\"!!!"
  return 0
}

function build_xmlsec {
  # check if already built
  xmlsec_version_without_rc=`echo "${xmlsec_version}" | sed 's/-rc.*//g'`
  full_name="xmlsec1-${xmlsec_version}"
  full_name_without_rc="xmlsec1-${xmlsec_version_without_rc}"
  full_url="https://www.aleksey.com/xmlsec/download/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name_without_rc}" -a -d "${xmlsec_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Folder \"${work_dir}\\${full_name_without_rc}\" and/or \"${xmlsec_output_dir}\" are missing, rebuilding ${full_name}"
  fi

  # build it!
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name_without_rc}" "${xmlsec_output_dir}"

  if [ ! -f "${full_name}.tar.gz" ] ; then
    echo "*** Downloading ${full_name}..."
    wget "${full_url}"
  else
    echo "*** File \"${full_name}.tar.gz\" already exists"
  fi

  echo "*** Extracting \"${full_name}\" archive..."
  tar xvfz "${full_name}.tar.gz" 2>> "${LOG_FILE}"

  echo "*** Configuring \"${full_name}\" ..."
  cd "${full_name_without_rc}\win32"
  cscript configure.js pedantic=yes werror=yes with-dl=yes cruntime=/MD xslt=yes crypto=openssl,mscng unicode=yes prefix="${xmlsec_output_dir}" include="${libxml2_output_dir}\include;${libxml2_output_dir}\include\libxml2;${libxslt_output_dir}\include;${openssl_output_dir}\include" lib="${libxml2_output_dir}\lib;${libxslt_output_dir}\lib;${openssl_output_dir}\lib"


  echo "*** Building \"${full_name}\" ..."
  nmake >> "${LOG_FILE}"

  echo "*** Installing \"${full_name}\" ..."
  nmake install >> "${LOG_FILE}"

  echo "*** Done with \"${full_name}\"!!!"
  return 0
}

function create_readme {
  echo "*** Creating README..."
  cd "${pwd}"
  cat "${script_dir}\\README-WINDOWS.md.in" | sed "s/@libxml2_version@/${libxml2_version}/g" |  sed "s/@libxslt_version@/${libxslt_version}/g" |  sed "s/@openssl_version@/${openssl_version}/g" |  sed "s/@xmlsec_version@/${xmlsec_version}/g" > "${distro_dir}\\README.md"
  echo "*** Done with README!!!"
  return 0
}

function create_distro {
  echo "*** Creating zip file..."
  cd "${distro_dir}"
  for ii in ${zip_folders_and_files} ; do
    echo "*** Removing pdb files from ${ii}..."
    rm -f ${ii}/bin/*.pdb ${ii}/bin/*/*.pdb ${ii}/lib/*.pdb  ${ii}/lib/*/*.pdb
  done
  rm -f "${zip_output_file}"
  zip -r "${zip_output_file}" ${zip_folders_and_files} >> "${LOG_FILE}"
  echo "*** Done with zip file: \"${zip_output_file}\""
  return 0

}

rm "${LOG_FILE}"
echo "*** LOG FILE: \"${LOG_FILE}\""

build_libxml2
build_libxslt
build_openssl
build_xmlsec
create_readme
create_distro

exit 0


