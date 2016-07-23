#DEXID - a classes.dex dumper and identifier

##Introduction

DEXID is a script written in Perl for displaying the contents of the 
`classes.dex` file (the file, which contains the bytecode in the `APK` files) and 
also for obtaining identification data for Android malware and using the 
obtained data to identify known such malware.

##Installation

DEXID is a self-contained script, which optionally uses a database of 
identification data for the known Android malware. No special installation for 
the script itself is required - just put it somewhere and run it from there. The 
database, however, if present, must reside in the same directory as the script. 
It must also have the same file name as the script and must have the extension 
"`.dat`". For instance, if the script is named `dexid.bat` and resides in the 
directory `c:\scipts`, then the database must be named `dexid.dat` and must also 
reside in `c:\scripts`.

Since DEXID is written in Perl, you'll need to have Perl installed, in order 
to run the script. Most Linux environments have Perl already installed. Windows 
users can install and use the free ActivePerl implementation, available from 
[ActiveState's](http://www.activestate.com/activeperl/downloads) site.

In addition, DEXID uses several non-standard Perl modules. "Non-standard" 
means that they are not present on your system by default (i.e., after 
installing Perl) and that you have to install them manually. Normally, 
ActivePerl users would use the program "`ppm`" which provides a GUI for installing 
new Perl modules. Unfortunately, several of the modules used by the script 
(e.g., the `Digest::*` modules) are not available from the ActiveState repository. 
This means that you'll have to install them from the CPAN repository, using an 
awkward command-line interface.

First, start Perl like this:

	perl -MCPAN -e shell

This should start the Perl shell, loading the module for interaction with the 
CPAN repository and the prompt "`cpan>`" should appear. At this prompt, enter the 
command "`install`", followed by the exact name of the module you want to install, 
for instance:

	cpan> install Digest::Adler32

Repeat this command for all the modules that are missing from your system. Here 
is the list of modules used by the script; some of them are almost certainly 
already present by default:

	strict
	warnings
	Fcntl
	Pod::Usage
	Getopt::Long
	Switch
	IO::File
	File::Spec
	Cwd
	LWP::Simple
	HTTP::Status
	Set::Scalar
	Digest::CRC
	Digest::MD5
	Digest::SHA
	Digest::Adler32
	Archive::Zip

Linux users should do pretty much the same, except that they are probably 
already used to awkard command-line interfaces. :-)

##Usage

DEXID takes one of eight possible options (all options are mutually exclusive) 
and one or more arguments. An argument can be a `DEX` file, an `APK` file (which is 
essentially a `ZIP` file and should contain a file named "`classes.dex`" in its root 
directory), a directory, or a file name beginning with the "`@`" character.

If a `DEX` or an `APK` file is provided as an argument (the file extension doesn't 
matter; the script determines the file type from its contents), this `DEX` file 
(or the `classes.dex` file inside the `APK` file) is processed by the script. (How 
exactly it is processed depends on the command-line options used; see below.)

If a directory is provided as an argument, all files and directories in it will 
be processed recursively.

If a file name preceded by the "`@`" character is provided as an argument, the "`@`" 
character is stripped from it and the rest is assumed to be a valid file name. 
The file should be an ASCII text file, containing one argument per line. Each 
such argument is processed by the script as if it were supplied from the command 
line. This is helpful when a lot of files in different directories have to be 
processed in a batch.

While the script is working, if it is processing directories, it outputs the 
name of the directory currently being processed to stderr, unless the `-s` option 
is used.

Under Windows, the script can be used as an executable `BAT` file:

	c:>dexid options arguments

On Linux, you'll have to specify it as a script file when invoking Perl:

	$ perl -f dexid.bat options arguments

###Command-line options

DEXID accepts the following command-line options:

`--help`	Prints a short help message, showing the usage of the script and exits.

`--ver`	Displays the version of the script, as well as the version of Perl and 
	`Getopt::Long::GetOptions` module used.

`-c`	Only lists the names of the classes in the `DEX` file. No attempt is made
	to dump their contents, to checksum them, or to identify any possible
	malware present. This mode of operation is very fast, though.

`-k`	Checks the database for any duplicate entries and exits, ignoring any
	other arguments.

`-l`	Lists the names of the malare for which entries exist in the database
	and exits, ignoring any other arguments.

`-m`	Use MD5 instead of SHA256 hashes (deprecated).

`-s`	Runs in silent mode, without displaying anything. Only returns an
	error level (`0` - nothing detected, `1` - something detected).

`-t`	Runs in identification-only mode. The only thing that is displayed is
	the file name and whether some malware has been found in it - no class
	names or identification data.

`-u`	Make sure your local copy of the database is the same as the remote
	("official") one. ATTENTION! If you have made changes to your local
	copy, they will be lost!

`-v`	Runs in verbose mode. Practically the whole contents of the `DEX` file
	is dumped in human-readable form, including disassembly of the bytecode
	instructions. At the beginning, the file name is listed in the format
	`<path><APKfile>->classes.dex (<Hash_of_APK_file>-><Hash_of_classes.dex>)`

`-d db`	Specifies the name of the file ("`db`") where the database is. If not
	specified, the database name is constructed by taking the name of the
	script, removing its extension, if any, and appending the extension
	"`.dat`" to the result. You can specify multiple databases by using this
	option more than once; their contents is concatenated together.

###Format of the database

The database of known Android malware used by the tool has a very simple format. 
It is an ASCII text files, containing entries. Each entry describes one 
particular Android malware variant. The entries are separated by one or more 
blank lines. A blank line is a line containing only white space, or white space 
followed by a comment character ("`#`").

It is possible to use "special comments" - the comment character ("`#`"), followed
by the "`@`" character, followed by a keyword. The letter case of the keyword is
not important. Currently, only the "`include`" keyword is supported. When it is
used, it is supposed to be followed by a valid file name. If the file name
contains spaces, surround it by single or double quotes. The contents of the
file, the name of which is specified after the "`include`" keyword is supposed
to be another valid database with entries; its contents is included at this
place. Some trivial checking is done, in order to prevent the inclusion of the
same database file more than once, because this could cause infinite loops.

The first word on the first line of each entry is considered to be the name of 
the malware. (As a consequence, the name must not contain spaces.) It is 
strongly suggested to use the [CARO malware naming scheme](http://www.caro.org/articles/naming.html), where each malware 
variant name has the format

	<malware_type>://<platform>.<family>.<variant>

For instance:

	trojan://AndroidOS/Adrd.A

(The variant names should be sequential letters - `A`, `B`, ... `Z`, `AA`, `AB`, ... `AZ`, 
`AAA`, `AAB`, ...)

The next lines of the entry contain identification data for the malicious 
classes, one class per line. The first word of each line is considered to be a 
checksum of the constant areas in the class, as computed by the script. 
Everything else on the line is ignored, but it is a good practice to keep the 
full class name after its checksum, for clarity.

The latest official version of the database is available from [there](http://dl.dropbox.com/u/34034939/dexid.dat).

You can either download it directly from the above site, Or you could use `-u` option to make
`dexid` fetch it automatically.

###Malware reports

The script defines a malware variant for the Android platform as a set of 
malicious classes. This is why the database entry consists of a list of 
checksums of such classes. When analyzing a DEX file, the script builds a set of 
the checksums of all classes in it. Identification, then, is performed on a set 
basis, using the sets from the database. The following detection reports are 
possible:

- No report. The set of classes in the examined `DEX` file is disjoint from any 
malicious sets listed in the database. That is, there are no common classes 
between them.

- "`(Exact)`". An entry exists in the database, which is an exact subset to the 
set of classes in the examined DEX file, or is identical to it. If more than one 
such database entries exist, the largest one will be used. If more than one 
entry in the database qualify as such (because the entries have the same size), 
the last one found will be used.

- "`(Remnants)`". The set of classes found in the examined `DEX` file is a subset of 
a database entry. If this subset is viable on its own, it is a new, so far 
unknown variant from the same malware family.

- "`(New variant)`". The intersection between the set of classes in the examined 
`DEX` file and at least one entry in the database is non-empty - i.e., they 
contain common classes, although no complete match could be found. This usually 
indicates a new variant from the same malware family - unless, of course, some 
improper database entry includes a class from a legitimate package and is 
causing a false positive. The script reports the entry from the database which 
has the largest common subset of classes with the examined file. If several such 
entries exist, the last one found is used.

###Caveats

1. This is a tool for determining whether a particular sample is known malware 
or not. It is NOT a general-purpose malware scanner. If you run it on your whole 
collection, it will take many hours (days? weeks?) and will probably crash.

2. When used in verbose mode, the tool generates A LOT of output. A large and 
complex `DEX` file (a couple of megabytes) could easily generate several _gigabytes_ 
of output.

3. When the script claims that something has been identified exactly, it means 
it. Trust me on this. Even a single-bit modification of the non-variable areas 
will be detected as not being exactly the same as the known malware variants.

4. Although in some very limited cases the script is able to determine that some 
new malware is a variant of a known malware family, do not rely on this 
extensively. This is not a tool for comparing the similarities between different 
malware variants.

5. Do not rely blindly on the output of the tool and do not add entries to the 
database yourself, unless you know perfectly well what you are doing. In 
particular, you __must__ have analyzed manually the malware and must understand very 
well how it works and what its structure is. If you do not, you're running the 
risk of creating a database entry, which will cause both false positives (e.g., 
if it includes classes from a legitimate package) and false negatives (if it 
includes classes with variable contents).

6. The script uses a Perl module for reading `ZIP` archives. Therefore, its 
processing of `APK` files (which are `ZIP` archives) is as good as this module. The 
archive might have a minor corruption (e.g., a CRC mismatch) which would not 
prevent the `APK` package from being installed or `WinZIP` from unpacking it, but 
which would cause the Perl module to refuse to process the archive. In such 
cases, the script will not display any information about the contents of the `DEX` 
file inside.

##Announcing Android malware with DEXID

_Do not_ attempt to create new database entries, unless you have personally 
analyzed the malware. If you do not heed this advice, you are likely to screw 
up, making the life difficult for everybody.

The script can facilitate the analysis when used in verbose mode (the `-v` 
option), since then it displays all kinds of information about the file, 
including a disassembly of the bytecode instructions. However, other tools like 
`baksmali`, `ddx` or `dex2jar`/`jd-gui` are vastly superior for this purpose.

Once you have analyzed the new sample of malware (and have determined that it 
is, indeed, malware), use the `-c` option to list all classes in the sample you 
have found. In our example, we'll use an `Adrd` variant:

```
geinimi.apk->classes.dex (5192AD05597E7A148F642BE43F6441F6->5F86B2E2C2D6BCCA1F580F9B5F444F6D)
	com.tat.cascadeswallpaper.android.CascadesWallpaperService$CascadesEngine$1
	com.tat.cascadeswallpaper.android.CascadesWallpaperService$CascadesEngine
	com.tat.cascadeswallpaper.android.CascadesWallpaperService$Config
	com.tat.cascadeswallpaper.android.CascadesWallpaperService
	com.tat.cascadeswallpaper.android.Log
	com.tat.livewallpaper.dandelion.Dandelion$1
	com.tat.livewallpaper.dandelion.Dandelion$2
	com.tat.livewallpaper.dandelion.Dandelion
	com.xxx.yyy.APNMatchTools$APNNet
	com.xxx.yyy.APNMatchTools
	com.xxx.yyy.ApkReceiver
	com.xxx.yyy.BBBB$LogRedirectHandler
	com.xxx.yyy.BBBB
	com.xxx.yyy.CustomBroadcastReceiver$CustomPhoneStateListener
	com.xxx.yyy.CustomBroadcastReceiver
	com.xxx.yyy.GZipInputStream
	com.xxx.yyy.GZipOutputStream
	com.xxx.yyy.MyAlarmReceiver
	com.xxx.yyy.MyBoolService
	com.xxx.yyy.MyService$APN
	com.xxx.yyy.MyService
	com.xxx.yyy.MyTools
	com.xxx.yyy.NetWorkReceiver
	com.xxx.yyy.UpdateHelper
	com.xxx.yyy.ZipHelper
	com.xxx.yyy.ZipIntMultShortHashMap$Element
	com.xxx.yyy.ZipIntMultShortHashMap
	com.xxx.yyy.ZipUtil
	com.xxx.yyy.adad$1
	com.xxx.yyy.adad
	com.xxx.yyy.ddda
	com.xxx.yyy.qzl$1
	com.xxx.yyy.qzl
```

This report helps identify the particular file (with the hashes of the `APK` 
file and of the `DEX` file inside it) and it also lists all classes in the sample, 
which is informative. Post this information as part of your announcement of the 
new malware. (This step is not necessary, if your analysis has shown that _all_ 
classes in the malware sample are malicious.)

Then use the script without any options, to compute identification data for the 
classes:

```
geinimi.apk->classes.dex (5192AD05597E7A148F642BE43F6441F6->5F86B2E2C2D6BCCA1F580F9B5F444F6D)
	DF15A764 com.tat.cascadeswallpaper.android.CascadesWallpaperService$CascadesEngine$1
	A3198019 com.tat.cascadeswallpaper.android.CascadesWallpaperService$CascadesEngine
	807E167B com.tat.cascadeswallpaper.android.CascadesWallpaperService$Config
	F40DA25E com.tat.cascadeswallpaper.android.CascadesWallpaperService
	A2338983 com.tat.cascadeswallpaper.android.Log
	0A5F391C com.tat.livewallpaper.dandelion.Dandelion$1
	E5DF2C1F com.tat.livewallpaper.dandelion.Dandelion$2
	4FB5DDF5 com.tat.livewallpaper.dandelion.Dandelion
	7E8BE144 com.xxx.yyy.APNMatchTools$APNNet
	08EA684E com.xxx.yyy.APNMatchTools
	A490446D com.xxx.yyy.ApkReceiver
	3902FF59 com.xxx.yyy.BBBB$LogRedirectHandler
	25B4A7E3 com.xxx.yyy.BBBB
	7E4A5825 com.xxx.yyy.CustomBroadcastReceiver$CustomPhoneStateListener
	8D27A0C1 com.xxx.yyy.CustomBroadcastReceiver
	5CAB2F0B com.xxx.yyy.GZipInputStream
	016FD1D4 com.xxx.yyy.GZipOutputStream
	DC1AC823 com.xxx.yyy.MyAlarmReceiver
	EC712BE9 com.xxx.yyy.MyBoolService
	E4EA5C7B com.xxx.yyy.MyService$APN
	092E62A6 com.xxx.yyy.MyService
	B6EB634B com.xxx.yyy.MyTools
	9C18FE76 com.xxx.yyy.NetWorkReceiver
	E468FE5A com.xxx.yyy.UpdateHelper
	7ED8B247 com.xxx.yyy.ZipHelper
	96088089 com.xxx.yyy.ZipIntMultShortHashMap$Element
	B780C5D6 com.xxx.yyy.ZipIntMultShortHashMap
	9C230B97 com.xxx.yyy.ZipUtil
	3CE2C554 com.xxx.yyy.adad$1
	123631AD com.xxx.yyy.adad
	0979EFEB com.xxx.yyy.ddda
	485C4EDE com.xxx.yyy.qzl$1
	BE451A3A com.xxx.yyy.qzl
```

Hopefully, at this point your manual analysis of the malware has shown you that 
the malicious classes are only those in the `com.xxx.yyy.*` subtree. Remove the 
other identification data, since it is not relevant to the malware variant. At 
this point, also remove any of the identification data for those malicious 
classes, for which your analysis has shown you that they are either variable 
(e.g., because they contain instruction to invoke a module in the legitimate 
package, which has been Trojanized by the malware author, and the operand of 
this instruction depends on the names of those legitimate classes), or which are 
likely to be included in legitimate packages (e.g., because they contain a 
publicly known exploit for rooting the device). In our particular example the 
malware does not contain any such classes, but other malware variants do contain 
them.

Choose an appropriate name for the malware (preferably - following the [CARO 
Malware Naming Scheme](http://www.caro.org/articles/naming.html)) and replace the file name in the above report with it. 
Post the result as part of your announcement of the new malware:

```
trojan://AndroidOS/Adrd.A
	7E8BE144 com.xxx.yyy.APNMatchTools$APNNet
	08EA684E com.xxx.yyy.APNMatchTools
	A490446D com.xxx.yyy.ApkReceiver
	3902FF59 com.xxx.yyy.BBBB$LogRedirectHandler
	25B4A7E3 com.xxx.yyy.BBBB
	7E4A5825 com.xxx.yyy.CustomBroadcastReceiver$CustomPhoneStateListener
	8D27A0C1 com.xxx.yyy.CustomBroadcastReceiver
	5CAB2F0B com.xxx.yyy.GZipInputStream
	016FD1D4 com.xxx.yyy.GZipOutputStream
	DC1AC823 com.xxx.yyy.MyAlarmReceiver
	EC712BE9 com.xxx.yyy.MyBoolService
	E4EA5C7B com.xxx.yyy.MyService$APN
	092E62A6 com.xxx.yyy.MyService
	B6EB634B com.xxx.yyy.MyTools
	9C18FE76 com.xxx.yyy.NetWorkReceiver
	E468FE5A com.xxx.yyy.UpdateHelper
	7ED8B247 com.xxx.yyy.ZipHelper
	96088089 com.xxx.yyy.ZipIntMultShortHashMap$Element
	B780C5D6 com.xxx.yyy.ZipIntMultShortHashMap
	9C230B97 com.xxx.yyy.ZipUtil
	3CE2C554 com.xxx.yyy.adad$1
	123631AD com.xxx.yyy.adad
	0979EFEB com.xxx.yyy.ddda
	485C4EDE com.xxx.yyy.qzl$1
	BE451A3A com.xxx.yyy.qzl
```

This information, if the above guidelines are properly followed, is an entry, 
ready to be included in the database. Once it is included there, the script will 
start identifying this malware by its assigned name.

##License

I am not a lawyer (which is why I've put this stuff at the end, instead of at 
the beginning) and I am not going to bore you with legalese. I'll spell in 
simple words what you may and what you may not do with this script.

1. This script is my work, I am its author and it is copyrighted by me. It is 
__NOT__ in the public domain, I own the rights on it and you may do with it only 
what I explicitly allow you to do.

2. You __MAY__ use this script for free for any purpose - commercial or otherwise.

3. You __MAY NOT__ modify this script, unless explicitly permitted to do so. If you 
want some additional features - ask me. I'll either implement them myself, or 
will allow you to make them.

4. You __MAY NOT__ redistribute this script, especially not modified versions of it. 
I want to retain full control on its development.

5. You __MAY__ use any useful ideas you find in this script. If you feel like it, 
you are free to rewrite it into another language and do with the result whatever 
you want. I retain rights only on this script.

6. You __MAY__ use portions of this script directly (i.e., in another Perl script) 
__ONLY__ if you credit me somewhere in your work as the author of these portions.

##Change log

Version 1.00	Initial version.

Version 1.01	I had specified "`Archive::ZIP`" instead of "`Archive::Zip`" (the
		real name of the module). Letter case matters in OSes like Linux,
		duh! Fixed.

Version 1.02	Was checksumming a byte, some bits of which can be variable.
		Fixed.
		Renamed the script from DEXDUMP to DEXID, in order to avoid a
		name conflict with a tool named "`dexdump`" which is distributed
		with the Android SDK.

Version 1.03	The code for determining the name of the database file from the
		name of the script was wrong and wouldn't work correctly if the
		name of the script contained dots other than the one separating
		the file name from the file extension. Fixed now, I hope.

Version 1.04	Now the script handles correctly the name of the database, if
		the name of the script has no extension (i.e., contains no dots).
		Implemented the `-u` option for getting the latest "official" copy
		of the database. (ATTENTION! Any changes to your local copy of
		the database will be lost!)

Version 1.05	The hash of stand-alone `classes.dex` files was not
		computed correctly. Fixed.

Version 1.06	Added the `-d` option for specifying databases other than the
		default one.

Version 1.07	The `-d` option now can be used multiple times, to specify several
		different databases.

Version 1.08	Fixed a bug in the disassembler (only the lower 16 bits of some
		32-bit constants were disassembled) and changed a bit the format
		of the operand of the branch transfer instructions (`if`s and
		`goto`s).

Version 1.09	Switched to using SHA256 instead of MD5 by default.
		Made the program behave gracefully when neither `dexid.dat`, nor
		any other database exists at all, instead of throwing an error.
