#!/bin/bash
#
# Must be run from the x64 Native Tools Command Prompt.
#
# $ c:\cygwin64\bin\bash build_windows.sh
#
libxml2_version="2.15.1"
libxslt_version="1.1.45"
openssl_version="3.6.0"
xmlsec_version="1.3.10-preview-1"

pwd=`pwd`
script_dir=`dirname $0`
work_dir=`cygpath "d:\\home\\aleksey\\dev"`
distro_dir="d:\\home\\aleksey\\distro"
libxml2_output_dir="${distro_dir}\libxml2"
libxslt_output_dir="${distro_dir}\libxslt"
openssl_output_dir="${distro_dir}\openssl"
xmlsec_output_dir="${distro_dir}\xmlsec"

zip_folders_and_files="libxml2 libxslt openssl xmlsec README.md"
zip_output_file="${distro_dir}\\xmlsec1-${xmlsec_version}-win64.zip"

PERL_PATH="C:\\Strawberry\\perl\\bin"
LOG_FILE=`cygpath "d:\\home\\aleksey\\tmp\\build-windows.log"`

CMAKE_XMLSEC_BUILDDIR=builddir
CMAKE_XMLSEC_ARCH="x64"
CMAKE_XMLSEC_GENERATOR="Visual Studio 17 2022"
CMAKE_XMLSEC_RUNTIME="MultiThreadedDLL"
CMAKE_XMLSEC_CONFIG=Release
CMAKE_XMLSEC_SHARED_LIBS=ON

function build_libxml2 {
  # Check whether the component is already built.
  full_name="libxml2-v${libxml2_version}"
  full_url="https://gitlab.gnome.org/GNOME/libxml2/-/archive/v${libxml2_version}/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name}" -a -d "${libxml2_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name}\" or \"${libxml2_output_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
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
  cd "${full_name}"
  cmake -B "${CMAKE_XMLSEC_BUILDDIR}" -A "${CMAKE_XMLSEC_ARCH}" -G "${CMAKE_XMLSEC_GENERATOR}" \
	  -D CMAKE_MSVC_RUNTIME_LIBRARY="${CMAKE_XMLSEC_RUNTIME}" \
	  -D BUILD_SHARED_LIBS="${CMAKE_XMLSEC_SHARED_LIBS}" \
	  -D CMAKE_PREFIX_PATH="${distro_dir}" \
	  -D CMAKE_INSTALL_PREFIX="${libxml2_output_dir}" \
	  -D LIBXML2_WITH_ICONV=OFF \
	  -D LIBXML2_WITH_PYTHON=OFF \
	  -D LIBXML2_WITH_ZLIB=OFF \
      -D LIBXML2_WITH_TESTS=OFF
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Building \"${full_name}\" ..."
  cmake --build "${CMAKE_XMLSEC_BUILDDIR}" --config "${CMAKE_XMLSEC_CONFIG}" >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Installing \"${full_name}\" ..."
  cmake --install "${CMAKE_XMLSEC_BUILDDIR}" --config "${CMAKE_XMLSEC_CONFIG}" >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Done with \"${full_name}\"!!!"
  return 0
}

function build_libxslt {
  # Check whether the component is already built.
  full_name="libxslt-v${libxslt_version}"
  full_url="https://gitlab.gnome.org/GNOME/libxslt/-/archive/v${libxslt_version}/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name}" -a -d "${libxslt_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name}\" or \"${libxslt_output_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
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

  cd "${full_name}"
  cmake -B "${CMAKE_XMLSEC_BUILDDIR}" -A "${CMAKE_XMLSEC_ARCH}" -G "${CMAKE_XMLSEC_GENERATOR}" \
	  -D CMAKE_MSVC_RUNTIME_LIBRARY="${CMAKE_XMLSEC_RUNTIME}" \
	  -D BUILD_SHARED_LIBS="${CMAKE_XMLSEC_SHARED_LIBS}" \
	  -D CMAKE_PREFIX_PATH="${distro_dir}" \
	  -D CMAKE_INSTALL_PREFIX="${libxslt_output_dir}" \
	  -D LIBXSLT_WITH_PYTHON=OFF \
      -D LIBXSLT_WITH_TESTS=OFF
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Building \"${full_name}\" ..."
  cmake --build "${CMAKE_XMLSEC_BUILDDIR}" --config "${CMAKE_XMLSEC_CONFIG}" >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Installing \"${full_name}\" ..."
  cmake --install "${CMAKE_XMLSEC_BUILDDIR}" --config "${CMAKE_XMLSEC_CONFIG}" >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Done with \"${full_name}\"!!!"
  return 0
}

function build_openssl {
  # Check whether the component is already built.
  full_name="openssl-${openssl_version}"
  full_url="https://github.com/openssl/openssl/releases/download/openssl-${openssl_version}/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name}" -a -d "${openssl_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name}\" or \"${openssl_output_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
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
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Building \"${full_name}\" ..."
  nmake >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Installing \"${full_name}\" ..."
  nmake install_sw >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Done with \"${full_name}\"!!!"
  return 0
}

function build_xmlsec {
  # Check whether the component is already built.
  xmlsec_version_without_rc=`echo "${xmlsec_version}" | sed 's/-rc.*//g' | sed 's/-preview.*//g'`
  full_name="xmlsec1-${xmlsec_version}"
  full_name_without_rc="xmlsec1-${xmlsec_version_without_rc}"
  full_url="https://www.aleksey.com/xmlsec/download/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name_without_rc}" -a -d "${xmlsec_output_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name_without_rc}\" or \"${xmlsec_output_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
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
  cscript configure.js pedantic=yes static=no cruntime=/MD unicode=yes \
    xslt=yes crypto=openssl,mscng \
    prefix="${xmlsec_output_dir}" \
    include="${libxml2_output_dir}\include;${libxml2_output_dir}\include\libxml2;${libxslt_output_dir}\include;${openssl_output_dir}\include" \
    lib="${libxml2_output_dir}\lib;${libxslt_output_dir}\lib;${openssl_output_dir}\lib"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Building \"${full_name}\" ..."
  nmake >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Installing \"${full_name}\" ..."
  nmake install >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

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

if [ "z$1" = "zcleanup" ] ; then
  echo "*** CLEANUP ..."
  rm -rf "${libxml2_output_dir}" "${libxslt_output_dir}" "${openssl_output_dir}" "${xmlsec_output_dir}"
else
  echo "*** BUILD ..."
  build_libxml2
  if [ $? -ne 0 ]; then
    exit $?
  fi
  build_libxslt
  if [ $? -ne 0 ]; then
    exit $?
  fi
  build_openssl
  if [ $? -ne 0 ]; then
    exit $?
  fi
  build_xmlsec
  if [ $? -ne 0 ]; then
    exit $?
  fi
  create_readme
  if [ $? -ne 0 ]; then
    exit $?
  fi
  create_distro
  if [ $? -ne 0 ]; then
    exit $?
  fi
fi

exit 0
