
                             Windows port
                             ------------

This directory contains the files required to build this software on the
native Windows platform.

As a rule of thumb, the root of this directory contains files needed
to build the library using the command-line tools, while various
subdirectories contain project files for various IDEs.


  1. Building the library
  =============================================

Building from command line is the easiest, preferred and the only 
currently supported method. 

In order to build from the command-line you need to make sure that
your compiler works from the command line. This is not always the
case, often the required environment variables are missing. If you are
not sure, test if this works first. If it doesn't, you will first have
to configure your compiler suite to run from the command-line - please
refer to your compiler's documentation regarding that.

The first thing you want to do is configure the source. You can have
the configuration script do this automatically for you. The
configuration script is written in JScript, a Microsoft's
implementation of the ECMA scripting language. Almost every Windows
machine can execute this through the Windows Scripting Host. If your
system lacks the ability to execute JScript for some reason, you must
perform the configuration manually.

The second step is compiling the source and, optionally, installing it
to the location of your choosing.


  1.1 Configuring the source automatically
  ----------------------------------------

The configuration script accepts numerous options. Some of these
affect features which will be available in the compiled software,
others affect the way the software is built and installed. To see a
full list of options supported by the configuration script, run

  cscript configure.js help

from the win32 subdirectory. The configuration script will present you
the options it accepts and give a biref explanation of these. In every
case you will have two sets of options. The first set is specific to
the software you are building and the second one is specific to the
Windows port.

Once you have decided which options suit you, run the script with that
options. Here is an example:

  cscript configure.js prefix=c:\opt include=c:\opt\include 
    lib=c:\opt\lib debug=yes

The previous example will configure the process to install the library
in c:\opt, use c:\opt\include and c:\opt\lib as additional search
paths for the compiler and the linker and build executables with debug
symbols.

Note: Please do not use path names which contain spaces. This will
fail. Allowing this would require me to put almost everything in the
Makefile in quotas and that looks quite ugly with my
syntax-highlighting engine. If you absolutely must use spaces in paths
send me an email and tell me why. If there are enough of you out there
who need this, or if a single one has a very good reason, I will
modify the Makefile to allow spaces in paths.


  1.2 (Not) Configuring the source manually
  -----------------------------------------

The manual configuration is pretty straightforward, but I would
suggest rather to get a JScript engine and let the configure script do
it for you. This process involves editing the apropriate Makefile to
suit your needs, as well as manually generating certain *.h files from
their *.h.in sources.

If you really have no idea what I am talking about and ask yourself
what in Gods name do I mean with '*.h files and their *.h.in sources',
then you really should do an automatic configuration. Which files must
be generated and what needs to be done with their sources in order to
generate them is something people who have built this software before
allready know. You will not find any explanations for that
here. Please configure the source manually only if you allready know
what you must do. Otherwise, you have the choice of either getting a
precompiled binary distribution, or performing the automatic
configuration.

  1.3 Compiling
  -------------

After the configuration stage has been completed, you want to build
the software. To do that, type

  nmake

in the win32 subdirectory.When the building completes, you will find
the executable files in win32\binaries directory.
 
You can install the software into the directory you specified to the
configure script during the configure stage by typing

  nmake install

That would be it, enjoy.

  2. Building your appliation
  =============================================

On Windows there is no easy way to automatically configure compilation
options or paths. You have to do everything manualy. Start up your
favorite IDE or text editor and read on.
    
  2.1 Global Defines.
  ---------------------------------------------

If you want to use automatic crypto library configuration (xmlsec/crypto.h file)
you need to add one of the following global defines:

    #define XMLSEC_CRYPTO_OPENSSL
    #define XMLSEC_CRYPTO_GNUTLS
    #define XMLSEC_CRYPTO_NSS

Also you'll need to define all configuration parameters used during XML Security
Library compilation (XMLSEC_NO_AES, XMLSEC_NO_X509,...).

  2.1 Additional Global Defines for static linking.
  ---------------------------------------------

Also if you (*and only if*) are linking libraries staticaly, you'll need to add following
global defines:

  2.2 Setting include and library paths.
  ---------------------------------------------

As usual, you need to have correct include and library paths to xmlsec, libxml,
libxslt, iconv, openssl or any other library used in your application.

  2.3 Selecting correct Windows runtime libraries.
  ---------------------------------------------

Windows basically has 6 different C runtimes. The first one is called libc.lib 
and can only be linked to statically and used only in single-threaded mode.
The second one is also can only be linked staticaly and used in multi-threaded
mode. The third one is called msvcrt.dll and can only be linked to dynamically. 
These three then live in their debug and release incarnations, which results in 
six C runtimes. The rule is simple: exactly the same runtime must be used 
throughout the application. Client code *MUST* use the same runtime as XMLSec, 
LibXML, LibXSLT, OpenSSL or any other library used.

If you downloaded XMLSec, LibXML, LibXSLT and OpenSSL binaries from Igor's 
page then all libraries are all linked to msvcrt.dll ("Multithreaded DLL" 
(NOT DEBUG!); /MD compiler switch). The click-next click-finish wizardry 
from Visual Studio chooses the single-threaded libc.lib as the default 
when you create a new project. And this causes great problems because 
you program crashes on first IO operation, first malloc/free from different 
runtimes or something even more trivial.

Do not forget that if you need a different runtime for some reason, then 
you MUST recompile not only XMLSec, but LibXML, LibXSLT and OpenSSL as well.


March 2002, Igor Zlatkovic <igor@stud.fh-frankfurt.de>
