#!/bin/bash
#
# Must be run from the x64 Native Tools Command Prompt.
#
# To build the distribution, run the script with "build-release" or "build-debug" parameter:
#
# $ c:\cygwin64\bin\bash scripts\build_windows.sh build-release
# $ c:\cygwin64\bin\bash scripts\build_windows.sh build-debug
#
# To clean up the build, run the script with "cleanup-release" or "cleanup-debug" parameter:
#
# $ c:\cygwin64\bin\bash scripts\build_windows.sh cleanup-release
# $ c:\cygwin64\bin\bash scripts\build_windows.sh cleanup-debug
#
libxml2_version="2.15.2"
libxslt_version="1.1.45"
openssl_version="4.0.0"
xmlsec_version="1.3.11-rc1"

pwd=`pwd`
script_dir=`dirname $0`
work_dir=`cygpath "d:\\home\\aleksey\\dev"`
top_install_dir_prefix="d:\\home\\aleksey\\distro"
PERL_PATH="C:\\Strawberry\\perl\\bin"
LOG_FILE=`cygpath "d:\\home\\aleksey\\tmp\\build-windows.log"`

LIBXML2_LIBXSLT_CMAKE_BUILDDIR=builddir
LIBXML2_LIBXSLT_CMAKE_ARCH="x64"
LIBXML2_LIBXSLT_CMAKE_GENERATOR="Visual Studio 17 2022"
LIBXML2_LIBXSLT_CMAKE_SHARED_LIBS=ON

# figure out configuration
if [[ "$1" =~ '-release' ]] ; then
  top_install_dir="${top_install_dir_prefix}.release"
  LIBXML2_LIBXSLT_CMAKE_CONFIG=Release
  LIBXML2_LIBXSLT_CMAKE_RUNTIME="MultiThreadedDLL"
  OPEENSL_XMLSEC_CONFIG="--release"
  XMLSEC_CONFIG_OPTIONS="debug=no memcheck=no cruntime=/MD"
  ZIP_POSTFIX=""
  echo "*** DETECTED RELEASE CONFIGURATION..."
elif [[ "$1" =~ '-debug' ]] ; then
  top_install_dir="${top_install_dir_prefix}.debug"
  LIBXML2_LIBXSLT_CMAKE_CONFIG=Debug
  LIBXML2_LIBXSLT_CMAKE_RUNTIME="MultiThreadedDebugDLL"
  OPEENSL_XMLSEC_CONFIG="--debug"
  XMLSEC_CONFIG_OPTIONS="debug=yes memcheck=yes cruntime=/MDd"
  ZIP_POSTFIX="-debug"
  echo "*** DETECTED DEBUG CONFIGURATION..."
else
  echo "Usage: $0 [build-release|build-debug|cleanup-release|cleanup-debug]"
  exit 1
fi

# things that depend on the release vs debug build
libxml2_install_dir="${top_install_dir}\libxml2"
libxslt_install_dir="${top_install_dir}\libxslt"
openssl_install_dir="${top_install_dir}\openssl"
xmlsec_install_dir="${top_install_dir}\xmlsec"

zip_folders_and_files="libxml2 libxslt openssl xmlsec README.md"
zip_output_file="${top_install_dir}\\xmlsec1-${xmlsec_version}-win64${ZIP_POSTFIX}.zip"

function build_libxml2 {
  # Check whether the component is already built.
  full_name="libxml2-v${libxml2_version}"
  full_url="https://gitlab.gnome.org/GNOME/libxml2/-/archive/v${libxml2_version}/${full_name}.tar.gz"

  echo "*** Checking if ${full_name} is already built..."
  if [ -d "${work_dir}\\${full_name}" -a -d "${libxml2_install_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name}\" or \"${libxml2_install_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name}" "${libxml2_install_dir}"

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
  cmake -B "${LIBXML2_LIBXSLT_CMAKE_BUILDDIR}" -A "${LIBXML2_LIBXSLT_CMAKE_ARCH}" -G "${LIBXML2_LIBXSLT_CMAKE_GENERATOR}" \
	  -D CMAKE_MSVC_RUNTIME_LIBRARY="${LIBXML2_LIBXSLT_CMAKE_RUNTIME}" \
	  -D BUILD_SHARED_LIBS="${LIBXML2_LIBXSLT_CMAKE_SHARED_LIBS}" \
	  -D CMAKE_PREFIX_PATH="${top_install_dir}" \
	  -D CMAKE_INSTALL_PREFIX="${libxml2_install_dir}" \
	  -D LIBXML2_WITH_ICONV=OFF \
	  -D LIBXML2_WITH_PYTHON=OFF \
	  -D LIBXML2_WITH_ZLIB=OFF \
    -D LIBXML2_WITH_TESTS=OFF
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Building \"${full_name}\" ..."
  cmake --build "${LIBXML2_LIBXSLT_CMAKE_BUILDDIR}" --config "${LIBXML2_LIBXSLT_CMAKE_CONFIG}" >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Installing \"${full_name}\" ..."
  cmake --install "${LIBXML2_LIBXSLT_CMAKE_BUILDDIR}" --config "${LIBXML2_LIBXSLT_CMAKE_CONFIG}" >> "${LOG_FILE}"
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
  if [ -d "${work_dir}\\${full_name}" -a -d "${libxslt_install_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name}\" or \"${libxslt_install_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name}" "${libxslt_install_dir}"

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
  cmake -B "${LIBXML2_LIBXSLT_CMAKE_BUILDDIR}" -A "${LIBXML2_LIBXSLT_CMAKE_ARCH}" -G "${LIBXML2_LIBXSLT_CMAKE_GENERATOR}" \
	  -D CMAKE_MSVC_RUNTIME_LIBRARY="${LIBXML2_LIBXSLT_CMAKE_RUNTIME}" \
	  -D BUILD_SHARED_LIBS="${LIBXML2_LIBXSLT_CMAKE_SHARED_LIBS}" \
	  -D CMAKE_PREFIX_PATH="${top_install_dir}" \
	  -D CMAKE_INSTALL_PREFIX="${libxslt_install_dir}" \
	  -D LIBXSLT_WITH_PYTHON=OFF \
    -D LIBXSLT_WITH_TESTS=OFF
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Building \"${full_name}\" ..."
  cmake --build "${LIBXML2_LIBXSLT_CMAKE_BUILDDIR}" --config "${LIBXML2_LIBXSLT_CMAKE_CONFIG}" >> "${LOG_FILE}"
  if [ $? -ne 0 ]; then
    exit $?
  fi

  echo "*** Installing \"${full_name}\" ..."
  cmake --install "${LIBXML2_LIBXSLT_CMAKE_BUILDDIR}" --config "${LIBXML2_LIBXSLT_CMAKE_CONFIG}" >> "${LOG_FILE}"
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
  if [ -d "${work_dir}\\${full_name}" -a -d "${openssl_install_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name}\" or \"${openssl_install_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name}" "${openssl_install_dir}"

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
  perl Configure no-unit-test --prefix="${openssl_install_dir}" ${OPEENSL_XMLSEC_CONFIG} VC-WIN64A-HYBRIDCRT 
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
  if [ -d "${work_dir}\\${full_name_without_rc}" -a -d "${xmlsec_install_dir}" ] ; then
    echo "Found ${full_name}, skipping build"
    return 0
  else
    echo "Either \"${work_dir}\\${full_name_without_rc}\" or \"${xmlsec_install_dir}\" is missing; rebuilding ${full_name}."
  fi

  # Build it.
  cd "${work_dir}"
  rm -rf "${work_dir}\\${full_name_without_rc}" "${xmlsec_install_dir}"

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
  powershell -ExecutionPolicy Bypass -File configure.ps1 pedantic=yes static=no unicode=yes ${XMLSEC_CONFIG_OPTIONS}\
    xslt=yes crypto=openssl,mscng \
    prefix="${xmlsec_install_dir}" \
    include="${libxml2_install_dir}\include;${libxml2_install_dir}\include\libxml2;${libxslt_install_dir}\include;${openssl_install_dir}\include" \
    lib="${libxml2_install_dir}\lib;${libxslt_install_dir}\lib;${openssl_install_dir}\lib"
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
  cat "${script_dir}\\README-WINDOWS.md.in" | sed "s/@libxml2_version@/${libxml2_version}/g" |  sed "s/@libxslt_version@/${libxslt_version}/g" |  sed "s/@openssl_version@/${openssl_version}/g" |  sed "s/@xmlsec_version@/${xmlsec_version}/g" > "${top_install_dir}\\README.md"
  echo "*** Done with README!!!"
  return 0
}

function create_distro {
  echo "*** Creating zip file..."
  cd "${top_install_dir}"
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

if [[ "$1" =~ 'build-' ]] ; then
  echo "*** BUILD (top dir: ${top_install_dir})..."
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
  ls -la "${top_install_dir}"
  echo "*** Done with BUILD!!!"
elif [[ "$1" =~ 'cleanup-' ]] ; then
  echo "*** CLEANUP (top dir: ${top_install_dir})..."
  rm -rf "${libxml2_install_dir}" "${libxslt_install_dir}" "${openssl_install_dir}" "${xmlsec_install_dir}" "${top_install_dir}\\README.md"
  ls -la "${top_install_dir}"
  echo "*** Done with CLEANUP!!!"
else
  echo "Usage: $0 [build-release|build-debug|cleanup-release|cleanup-debug]"
  exit 1
fi

exit 0
