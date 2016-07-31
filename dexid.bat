@rem = '--*-Perl-*--
@echo off
if "%OS%" == "Windows_NT" goto WinNT
perl -x -S "%0" %1 %2 %3 %4 %5 %6 %7 %8 %9
goto endofperl
:WinNT
perl -x -S %0 %*
goto endofperl
@rem ';
#!/usr/bin/perl
#
#$Id: dexid.bat,v 1.09 2015/05/28 15:44:51 bontchev Exp $
#
# dexid
#
# Identifies exactly Android malware
#
# Copyright (C) 2011-2016 Vesselin Bontchev
#
# You can contact me via vbontchev@yahoo.com

use strict;
use warnings;
use Fcntl qw (:seek);
use Pod::Usage;
use Getopt::Long;
use Switch 'Perl5', 'Perl6';
use IO::File;
use File::Spec;
use Cwd;
use LWP::Simple;
use HTTP::Status qw(:constants :is status_message);
use Set::Scalar;
use Digest::CRC;
use Digest::MD5;
use Digest::SHA;
use Digest::Adler32;
use Archive::Zip qw (:ERROR_CODES :CONSTANTS);

my $listcls = 0;
my $chkdups = 0;
my $listdb = 0;
my $silent = 0;
my $idonly = 0;
my $update = 0;
my $verbose = 0;
my $identified = 0;
my $useMD5 = 0;
my @database;
my $database_path = "http://dl.dropbox.com/u/34034939/dexid.dat";

{
	my $arg;
	my $dexid_dat = $0;
	my @db_names;
	my %processed_databases;
	if (index ($dexid_dat, '.') < 0)
	{
		$dexid_dat .= ".dat";
	}
	else
	{
		$dexid_dat =~ s/\.[^\.]+$/\.dat/;
	}
	$main::VERSION = "1.10";
	Getopt::Long::Configure ('no_ignore_case', 'auto_version', 'auto_help');
	GetOptions (
		"c" => sub { $listcls = 1; $chkdups = 0; $listdb = 0; $silent = 0; $idonly = 0; $update = 0; $verbose = 0; },
		"k" => sub { $listcls = 0; $chkdups = 1; $listdb = 0; $silent = 0; $idonly = 0; $update = 0; $verbose = 0; },
		"l" => sub { $listcls = 0; $chkdups = 0; $listdb = 1; $silent = 0; $idonly = 0; $update = 0; $verbose = 0; },
		"m" => sub { $useMD5  = 1; },
		"s" => sub { $listcls = 0; $chkdups = 0; $listdb = 0; $silent = 1; $idonly = 0; $update = 0; $verbose = 0; },
		"t" => sub { $listcls = 0; $chkdups = 0; $listdb = 0; $silent = 0; $idonly = 1; $update = 0; $verbose = 0; },
		"u" => sub { $listcls = 0; $chkdups = 0; $listdb = 0; $silent = 0; $idonly = 0; $update = 1; $verbose = 0; },
		"v" => sub { $listcls = 0; $chkdups = 0; $listdb = 0; $silent = 0; $idonly = 0; $update = 0; $verbose = 1; },
		"d=s" => \@db_names
	);
	pod2usage (2) unless (defined ($ARGV [0]) || $listdb || $chkdups || $update);
	if ($update)
	{
		my $result = mirror ($database_path, $dexid_dat);
		if (is_error ($result))
		{
			printf STDERR ("Could not update the database: %s.\n", status_message ($result));
		}
		exit $identified;
	}
	if ($listdb || ! $listcls)
	{
		if ((scalar (@db_names) == 0) && (-e $dexid_dat))
		{
			push (@db_names, $dexid_dat);
		}
		foreach my $dbname (@db_names)
		{
			if (exists $processed_databases {$dbname})
			{
				printf STDERR ("Database file \"%s\" has already been processed.\n", $dbname);
			}
			else
			{
				%processed_databases = read_database ($dbname, %processed_databases);
			}
		}
	}
	if ($listdb)
	{
		#Set::Scalar->as_string_callback (sub { "(" . join (", ", map { sprintf ("0x%08X", $_) } sort ($_ [0]->elements)) . ")" });
		foreach my $entry (@database)
		{
			printf ("%s", @$entry [0]);
			#print ": ", @$entry [1];
			printf ("\n");
		}
		exit $identified;
	}
	if ($chkdups)
	{
		my $no_dups = 1;
		for (my $i = 0; $i < scalar (@database) - 1; $i++)
		{
			for (my $j = $i + 1; $j < scalar (@database); $j++)
			{
				if ($database [$i] [1]->compare ($database [$j] [1]) eq "equal")
				{
					printf ("Duplicate entries: %s, %s\n", $database [$i] [0], $database [$j] [0]);
					$no_dups = 0;
				}
			}
		}
		printf ("Database OK.\n") if ($no_dups);
		exit $identified;
	}
	foreach $arg (@ARGV)
	{
		process_arg ($arg);
	}
	exit $identified;
}

sub read_database
{
	my ($dexid_dat, %processed_databases) = @_;
	$processed_databases {$dexid_dat} = 1;
	my $INPUT = IO::File->new ($dexid_dat);
	if (! defined ($INPUT))
	{
		print STDERR "Canot open file \"$dexid_dat\"; possible reason: $!\n";
		return;
	}
	my $line;
	my $entry_found = 0;
	my $name;
	my $crcs;
	while (defined ($line = <$INPUT>))
	{
		if ($line =~ /^\s*#\@include/i)
		{
			$line =~ m/\@include\s+('[^']+'|"[^"]+"|.+?(?<!\\))\s/gi;
			my $fname = $1;
			$fname =~ s/\\([rnt'"\\ ])/"qq|\\$1|"/gee;
			$fname =~ s/^"(.*)"$/$1/s or
			$fname =~ s/^'(.*)'$/$1/s;
			$fname = File::Spec->canonpath (Cwd::realpath ($fname));
			if (File::Spec->case_tolerant ())
			{
				$fname =~ tr/A-Z/a-z/;
			}
			if (exists $processed_databases {$fname})
			{
				printf STDERR ("Database file \"%s\" has already been processed.\n", $fname);
			}
			else
			{
				%processed_databases = read_database ($fname, %processed_databases);
			}
			next;
		}
		next if ($line =~ /^\s*#/);
		if ($line =~ /^\s*$/)
		{
			if ($entry_found)
			{
				push (@database, [$name, $crcs]);
				$entry_found = 0;
			}
		}
		else
		{
			if ($entry_found)
			{
				$_ = $line;
				m/^\s*(\S+)/;
				$crcs->insert (hex ("0x" . $1));
			}
			else
			{
				$_ = $line;
				m/^\s*(\S+)/;
				$name = $1;
				$crcs = Set::Scalar->new;
			}
			$entry_found = 1;
		}
	}
	push (@database, [$name, $crcs]) if ($entry_found);
	close ($INPUT);
	return %processed_databases;
}

sub process_arg
{
	my ($arg) = @_;
	if (-d $arg)
	{
		process_dir ($arg);
	}
	else
	{
		if (substr ($arg, 0, 1) eq "@")
		{
			process_list (substr ($arg, 1));
		}
		else
		{
			process_file ($arg);
		}
	}
}

sub process_dir
{
	my ($dirpath) = @_;
	my ($name, $dir, @files);
	printf (STDERR "%s/\n", $dirpath);
	opendir ($dir, $dirpath);
	@files = readdir ($dir);
	closedir ($dir);
	foreach (@files)
	{
		next if (($_ eq '.') || ($_ eq '..'));
		$name = $dirpath . "/" . $_;
		if (-d $name)
		{
			process_dir ($name);
		}
		else
		{
			process_file ($name);
		}
	}
}

sub process_list
{
	my ($listfile) = @_;
	my $line;
	open (my $fh, $listfile) or warn "Can't open $listfile: $!";
	while (! eof ($fh))
	{
		defined ($line = <$fh>) or warn "readline failed for $listfile: $!";
		$line =~ s/\s+$//;
		process_arg ($line);
	}
}

sub get_byte
{
	my ($buffer, $offset) = @_;
	return unpack ('C', substr ($buffer, $offset, 1));
}

sub get_word
{
	my ($buffer, $offset) = @_;
	return unpack ('S', substr ($buffer, $offset, 2));
}

sub get_dword
{
	my ($buffer, $offset) = @_;
	return unpack ('L', substr ($buffer, $offset, 4));
}

sub get_long_type
{
	my ($type) = @_;
	my @types = (
		['V', "void"],
		['Z', "boolean"],
		['B', "byte"],
		['S', "short"],
		['C', "char"],
		['I', "int"],
		['J', "long"],
		['F', "float"],
		['D', "double"]
	);
	my $desc = $type;
	my $post = "";
	while (substr ($type, 0, 1) eq "[")
	{
		$post .= " []";
		$type = substr ($type, 1);
		return "ERROR" if (length ($type) <= 0);
	}
	if (substr ($type, 0, 1) eq "L")
	{
		$desc = substr ($type, 1);
		$desc =~ s/\//\./g;
		$desc =~ s/;$//g;
	}
	else
	{
		for my $row (@types)
		{
			if ($type eq @$row [0])
			{
				$desc = @$row [1];
				last;
			}
		}
	}
	return $desc . $post;
}

sub get_string_slow
{
	my ($buffer, $index, $string_offset) = @_;
	return "NO_INDEX" if ($index == 0xFFFFFFFF);
	my $str_offs = get_dword ($buffer, $string_offset + $index * 4);
	my $raw_name = substr ($buffer, $str_offs + 1, get_byte ($buffer, $str_offs));
	return $raw_name;
}

sub get_string_fast
{
	my ($strings, $str_idx) = @_;
	return $strings->[$str_idx];
}

sub get_type_slow
{
	my ($buffer, $type_id, $type_ids_offs, $string_offset) = @_;
	return "NO_INDEX" if ($type_id == 0xFFFFFFFF);
	return get_long_type (get_string_slow ($buffer, get_dword ($buffer, $type_ids_offs + $type_id * 4), $string_offset));
}

sub get_type_medium
{
	my ($buffer, $type_ids_offs, $strings, $type_idx) = @_;
	return "NO_INDEX" if ($type_idx == 0xFFFFFFFF);
	return get_long_type (get_string_fast ($strings, get_dword ($buffer, $type_ids_offs + $type_idx * 4)));
}

sub get_type_fast
{
	my ($types, $type_idx) = @_;
	return "NO_INDEX" if ($type_idx == 0xFFFFFFFF);
	return $types->[$type_idx];
}

sub get_access_flags
{
	my ($flags, $friendly, $field) = @_;
	my $string = "";
	my @flag_values = (
		"ACC_PUBLIC",
		"ACC_PRIVATE",
		"ACC_PROTECTED",
		"ACC_STATIC",
		"ACC_FINAL",
		"ACC_SYNCHRONIZED",
		"ACC_VOLATILE",
		"ACC_TRANSIENT",
		"ACC_NATIVE",
		"ACC_INTERFACE",
		"ACC_ABSTRACT",
		"ACC_STRICT",
		"ACC_SYNTHETIC",
		"ACC_ANNOTATION",
		"ACC_ENUM",
		"ACC_UNUSED",
		"ACC_CONSTRUCTOR",
		"ACC_DECLARED_SYNCHRONIZED"
	);
	my @friendly_flags = (
		"public",
		"private",
		"protected",
		"static",
		"final",
		"synchronized",
		"bridge",
		"varargs",
		"native",
		"interface",
		"abstract",
		"strict",
		"synthetic",
		"annotation",
		"enum",
		"unused",
		"constructor",
		"declared-synchronized"
	);
	if ($field)
	{
		$friendly_flags [6] = "volatile";
		$friendly_flags [7] = "transient";
	}
	for my $i (0 .. $#flag_values)
	{
		if ($flags & (1 << $i))
		{
			if ($friendly)
			{
				$string .= $friendly_flags [$i] . " ";
			}
			else
			{
				$string .= $flag_values [$i] . ", ";
			}
		}
	}
	return $string if ($friendly);
	$string =~ s/, $//;
	return sprintf ("%08X (%s)", $flags, $string);
}

sub get_uleb128
{
	my ($buffer, $offset) = @_;
	my $ubyte;
	my $length = 1;
	my $result = get_byte ($buffer, $offset);
	if ($result > 0x7F)
	{
		$ubyte = get_byte ($buffer, $offset + $length);
		$result = ($result & 0x7F) | (($ubyte & 0x7F) << 7);
		$length++;
		if ($ubyte > 0x7F)
		{
			$ubyte = get_byte ($buffer, $offset + $length);
			$result |= ($ubyte & 0x7F) << 14;
			$length++;
			if ($ubyte > 0x7F)
			{
				$ubyte = get_byte ($buffer, $offset + $length);
				$result |= ($ubyte & 0x7F) << 21;
				$length++;
				if ($ubyte > 0x7F)
				{
					$ubyte = get_byte ($buffer, $offset + $length);
					$result |= ($ubyte & 0x7F) << 28;
					$length++;
				}
			}
		}
	}
	return ($length, $result);
}

sub get_sleb128
{
	my ($buffer, $offset) = @_;
	my ($result, $shift, $size, $length) = (0, 0, 31, 0);
	my $ubyte;
	do
	{
		$ubyte = get_byte ($buffer, $offset + $length);
		$result |= ($ubyte & 0x7F) << $shift;
		$shift += 7;
		$length++;
	}
	while ($ubyte & 0x80);
	$result |= -(1 << $shift) if (($shift < $size) && ($ubyte & 0x40));
	$result = unpack ('l', pack ('L', $result));
	return ($length, $result);
}

sub get_method_slow
{
	my ($buffer, $method_offs, $proto_offs, $type_offs, $str_offs, $method_id) = @_;
	return "NO_INDEX" if ($method_id == 0xFFFFFFFF);
	my $offs = $method_offs + $method_id * 8;
	my $proto_idx = get_word ($buffer, $offs + 2);
	my $ret_val = get_type_slow ($buffer, get_dword ($buffer, $proto_offs + $proto_idx * 12 + 4), $type_offs, $str_offs);
	my $class_name = get_type_slow ($buffer, get_word ($buffer, $offs), $type_offs, $str_offs);
	my $method_name  = get_string_slow ($buffer, get_dword ($buffer, $offs + 4), $str_offs);
	my $param_offs = get_dword ($buffer, $proto_offs + $proto_idx * 12 + 8);
	my $params = "";
	if ($param_offs)
	{
		$params = "";
		my $num_params = get_dword ($buffer, $param_offs);
		for (my $parameter = 0; $parameter < $num_params; $parameter++)
		{
			$params .= get_type_slow ($buffer, get_word ($buffer, $param_offs + 4 + $parameter * 2), $type_offs, $str_offs);
			$params .= ", " if ($parameter + 1 < $num_params);
		}
	}
	return $ret_val . " " . $class_name . "." . $method_name . " (" . $params . ")";
}

sub get_method_medium
{
	my ($buffer, $method_idx, $method_offs, $proto_offs, $types, $strings) = @_;
	return "NO_INDEX" if ($method_idx == 0xFFFFFFFF);
	my $offs = $method_offs + $method_idx * 8;
	my $proto_idx = get_word ($buffer, $offs + 2);
	my $ret_val = get_type_fast ($types, get_dword ($buffer, $proto_offs + $proto_idx * 12 + 4));
	my $class_name = get_type_fast ($types, get_word ($buffer, $offs));
	my $method_name = get_string_fast ($strings, get_dword ($buffer, $offs + 4));
	my $param_offs = get_dword ($buffer, $proto_offs + $proto_idx * 12 + 8);
	my $params = "";
	if ($param_offs)
	{
		$params = "";
		my $num_params = get_dword ($buffer, $param_offs);
		for (my $parameter = 0; $parameter < $num_params; $parameter++)
		{
			$params .= get_type_fast ($types, get_word ($buffer, $param_offs + 4 + $parameter * 2));
			$params .= ", " if ($parameter + 1 < $num_params);
		}
	}
	return $ret_val . " " . $class_name . "." . $method_name . " (" . $params . ")";
}

sub get_method_fast
{
	my ($methods, $method_idx) = @_;
	return "NO_INDEX" if ($method_idx == 0xFFFFFFFF);
	return $methods->[$method_idx];
}

sub get_field_slow
{
	my ($buffer, $field_offs, $type_offs, $str_offs, $field_id) = @_;
	my $offs = $field_offs + $field_id * 8;
	my $class_idx  = get_word  ($buffer, $offs + 0);
	my $type_idx   = get_word  ($buffer, $offs + 2);
	my $name_idx   = get_dword ($buffer, $offs + 4);
	my $class_name = get_type_slow ($buffer, $class_idx, $type_offs, $str_offs);
	my $type_name  = get_type_slow ($buffer, $type_idx,  $type_offs, $str_offs);
	my $name_name  = get_string_slow ($buffer, $name_idx, $str_offs);
	return $type_name . " " . $class_name . "." . $name_name;
}

sub get_field_medium
{
	my ($buffer, $field_offs, $field_idx, $types, $strings) = @_;
	my $offs = $field_offs + $field_idx * 8;
	my $class_idx  = get_word  ($buffer, $offs + 0);
	my $type_idx   = get_word  ($buffer, $offs + 2);
	my $name_idx   = get_dword ($buffer, $offs + 4);
	my $class_name = get_type_fast ($types, $class_idx);
	my $type_name  = get_type_fast ($types, $type_idx);
	my $name_name  = get_string_fast ($strings, $name_idx);
	return $type_name . " " . $class_name . "." . $name_name;
}

sub get_field_fast
{
	my ($fields, $field_idx) = @_;
	return $fields->[$field_idx];
}

sub dump_instruction
{
	#my ($buffer, $offs, $string_offset, $type_offs, $field_offs, $method_offs, $proto_offs, $class_crc) = @_;
	my ($buffer, $offs, $strings, $types, $fields, $methods, $class_crc) = @_;
	my @opcodes = (
		# [opcode, mnemonic, format, ref_type]
		# ref types: 0 - none, 1 - string, 2 - type, 3 - field, 4 - method
		[0x00, "nop",                        "10x",  0],
		[0x01, "move",                       "12x",  0],
		[0x02, "move/from16",                "22x",  0],
		[0x03, "move/16",                    "32x",  0],
		[0x04, "move-wide",                  "12x",  0],
		[0x05, "move-wide/from16",           "22x",  0],
		[0x06, "move-wide/16",               "32x",  0],
		[0x07, "move-object",                "12x",  0],
		[0x08, "move-object/from16",         "22x",  0],
		[0x09, "move-object/16",             "32x",  0],
		[0x0A, "move-result",                "11x",  0],
		[0x0B, "move-result-wide",           "11x",  0],
		[0x0C, "move-result-object",         "11x",  0],
		[0x0D, "move-exception",             "11x",  0],
		[0x0E, "return-void",                "10x",  0],
		[0x0F, "return",                     "11x",  0],
		[0x10, "return-wide",                "11x",  0],
		[0x11, "return-object",              "11x",  0],
		[0x12, "const/4",                    "11n",  0],
		[0x13, "const/16",                   "21s",  0],
		[0x14, "const",                      "31i",  0],
		[0x15, "const/high16",               "21h",  0],
		[0x16, "const-wide/16",              "21s",  0],
		[0x17, "const-wide/32",              "31i",  0],
		[0x18, "const-wide",                 "51l",  0],
		[0x19, "const-wide/high16",          "21h",  0],
		[0x1A, "const-string",               "21c",  1],
		[0x1B, "const-string/jumbo",         "31c",  1],
		[0x1C, "const-class",                "21c",  2],
		[0x1D, "monitor-enter",              "11x",  0],
		[0x1E, "monitor-exit",               "11x",  0],
		[0x1F, "check-cast",                 "21c",  2],
		[0x20, "instance-of",                "22c",  2],
		[0x21, "array-length",               "12x",  0],
		[0x22, "new-instance",               "21c",  2],
		[0x23, "new-array",                  "22c",  2],
		[0x24, "filled-new-array",           "35c",  2],
		[0x25, "filled-new-array/range",     "3rc",  2],
		[0x26, "fill-array-data",            "31t",  0],
		[0x27, "throw",                      "11x",  0],
		[0x28, "goto",                       "10t",  0],
		[0x29, "goto/16",                    "20t",  0],
		[0x2A, "goto/32",                    "30t",  0],
		[0x2B, "packed-switch",              "31t",  0],
		[0x2C, "sparse-switch",              "31t",  0],
		[0x2D, "cmpl-float",                 "23x",  0],
		[0x2E, "cmpg-float",                 "23x",  0],
		[0x2F, "cmpl-double",                "23x",  0],
		[0x30, "cmpg-double",                "23x",  0],
		[0x31, "cmp-long",                   "23x",  0],
		[0x32, "if-eq",                      "22t",  0],
		[0x33, "if-ne",                      "22t",  0],
		[0x34, "if-lt",                      "22t",  0],
		[0x35, "if-ge",                      "22t",  0],
		[0x36, "if-gt",                      "22t",  0],
		[0x37, "if-le",                      "22t",  0],
		[0x38, "if-eqz",                     "21t",  0],
		[0x39, "if-nez",                     "21t",  0],
		[0x3A, "if-ltz",                     "21t",  0],
		[0x3B, "if-gez",                     "21t",  0],
		[0x3C, "if-gtz",                     "21t",  0],
		[0x3D, "if-lez",                     "21t",  0],
		[0x44, "aget",                       "23x",  0],
		[0x45, "aget-wide",                  "23x",  0],
		[0x46, "aget-object",                "23x",  0],
		[0x47, "aget-boolean",               "23x",  0],
		[0x48, "aget-byte",                  "23x",  0],
		[0x49, "aget-char",                  "23x",  0],
		[0x4A, "aget-short",                 "23x",  0],
		[0x4B, "aput",                       "23x",  0],
		[0x4C, "aput-wide",                  "23x",  0],
		[0x4D, "aput-object",                "23x",  0],
		[0x4E, "aput-boolean",               "23x",  0],
		[0x4F, "aput-byte",                  "23x",  0],
		[0x50, "aput-char",                  "23x",  0],
		[0x51, "aput-short",                 "23x",  0],
		[0x52, "iget",                       "22c",  3],
		[0x53, "iget-wide",                  "22c",  3],
		[0x54, "iget-object",                "22c",  3],
		[0x55, "iget-boolean",               "22c",  3],
		[0x56, "iget-byte",                  "22c",  3],
		[0x57, "iget-char",                  "22c",  3],
		[0x58, "iget-short",                 "22c",  3],
		[0x59, "iput",                       "22c",  3],
		[0x5A, "iput-wide",                  "22c",  3],
		[0x5B, "iput-object",                "22c",  3],
		[0x5C, "iput-boolean",               "22c",  3],
		[0x5D, "iput-byte",                  "22c",  3],
		[0x5E, "iput-char",                  "22c",  3],
		[0x5F, "iput-short",                 "22c",  3],
		[0x60, "sget",                       "21c",  3],
		[0x61, "sget-wide",                  "21c",  3],
		[0x62, "sget-object",                "21c",  3],
		[0x63, "sget-boolean",               "21c",  3],
		[0x64, "sget-byte",                  "21c",  3],
		[0x65, "sget-char",                  "21c",  3],
		[0x66, "sget-short",                 "21c",  3],
		[0x67, "sput",                       "21c",  3],
		[0x68, "sput-wide",                  "21c",  3],
		[0x69, "sput-object",                "21c",  3],
		[0x6A, "sput-boolean",               "21c",  3],
		[0x6B, "sput-byte",                  "21c",  3],
		[0x6C, "sput-char",                  "21c",  3],
		[0x6D, "sput-short",                 "21c",  3],
		[0x6E, "invoke-virtual",             "35c",  4],
		[0x6F, "invoke-super",               "35c",  4],
		[0x70, "invoke-direct",              "35c",  4],
		[0x71, "invoke-static",              "35c",  4],
		[0x72, "invoke-interface",           "35c",  4],
		[0x74, "invoke-virtual/range",       "3rc",  4],
		[0x75, "invoke-super/range",         "3rc",  4],
		[0x76, "invoke-direct/range",        "3rc",  4],
		[0x77, "invoke-static/range",        "3rc",  4],
		[0x78, "invoke-interface/range",     "3rc",  4],
		[0x7B, "neg-int",                    "12x",  0],
		[0x7C, "not-int",                    "12x",  0],
		[0x7D, "neg-long",                   "12x",  0],
		[0x7E, "not-long",                   "12x",  0],
		[0x7F, "neg-float",                  "12x",  0],
		[0x80, "neg-double",                 "12x",  0],
		[0x81, "int-to-long",                "12x",  0],
		[0x82, "int-to-float",               "12x",  0],
		[0x83, "int-to-double",              "12x",  0],
		[0x84, "long-to-int",                "12x",  0],
		[0x85, "long-to-float",              "12x",  0],
		[0x86, "long-to-double",             "12x",  0],
		[0x87, "float-to-int",               "12x",  0],
		[0x88, "float-to-long",              "12x",  0],
		[0x89, "float-to-double",            "12x",  0],
		[0x8A, "double-to-int",              "12x",  0],
		[0x8B, "double-to-long",             "12x",  0],
		[0x8C, "double-to-float",            "12x",  0],
		[0x8D, "int-to-byte",                "12x",  0],
		[0x8E, "int-to-char",                "12x",  0],
		[0x8F, "int-to-short",               "12x",  0],
		[0x90, "add-int",                    "23x",  0],
		[0x91, "sub-int",                    "23x",  0],
		[0x92, "mul-int",                    "23x",  0],
		[0x93, "div-int",                    "23x",  0],
		[0x94, "rem-int",                    "23x",  0],
		[0x95, "and-int",                    "23x",  0],
		[0x96, "or-int",                     "23x",  0],
		[0x97, "xor-int",                    "23x",  0],
		[0x98, "shl-int",                    "23x",  0],
		[0x99, "shr-int",                    "23x",  0],
		[0x9A, "ushr-int",                   "23x",  0],
		[0x9B, "add-long",                   "23x",  0],
		[0x9C, "sub-long",                   "23x",  0],
		[0x9D, "mul-long",                   "23x",  0],
		[0x9E, "div-long",                   "23x",  0],
		[0x9F, "rem-long",                   "23x",  0],
		[0xA0, "and-long",                   "23x",  0],
		[0xA1, "or-long",                    "23x",  0],
		[0xA2, "xor-long",                   "23x",  0],
		[0xA3, "shl-long",                   "23x",  0],
		[0xA4, "shr-long",                   "23x",  0],
		[0xA5, "ushr-long",                  "23x",  0],
		[0xA6, "add-float",                  "23x",  0],
		[0xA7, "sub-float",                  "23x",  0],
		[0xA8, "mul-float",                  "23x",  0],
		[0xA9, "div-float",                  "23x",  0],
		[0xAA, "rem-float",                  "23x",  0],
		[0xAB, "add-double",                 "23x",  0],
		[0xAC, "sub-double",                 "23x",  0],
		[0xAD, "mul-double",                 "23x",  0],
		[0xAE, "div-double",                 "23x",  0],
		[0xAF, "rem-double",                 "23x",  0],
		[0xB0, "add-int/2addr",              "12x",  0],
		[0xB1, "sub-int/2addr",              "12x",  0],
		[0xB2, "mul-int/2addr",              "12x",  0],
		[0xB3, "div-int/2addr",              "12x",  0],
		[0xB4, "rem-int/2addr",              "12x",  0],
		[0xB5, "and-int/2addr",              "12x",  0],
		[0xB6, "or-int/2addr",               "12x",  0],
		[0xB7, "xor-int/2addr",              "12x",  0],
		[0xB8, "shl-int/2addr",              "12x",  0],
		[0xB9, "shr-int/2addr",              "12x",  0],
		[0xBA, "ushr-int/2addr",             "12x",  0],
		[0xBB, "add-long/2addr",             "12x",  0],
		[0xBC, "sub-long/2addr",             "12x",  0],
		[0xBD, "mul-long/2addr",             "12x",  0],
		[0xBE, "div-long/2addr",             "12x",  0],
		[0xBF, "rem-long/2addr",             "12x",  0],
		[0xC0, "and-long/2addr",             "12x",  0],
		[0xC1, "or-long/2addr",              "12x",  0],
		[0xC2, "xor-long/2addr",             "12x",  0],
		[0xC3, "shl-long/2addr",             "12x",  0],
		[0xC4, "shr-long/2addr",             "12x",  0],
		[0xC5, "ushr-long/2addr",            "12x",  0],
		[0xC6, "add-float/2addr",            "12x",  0],
		[0xC7, "sub-float/2addr",            "12x",  0],
		[0xC8, "mul-float/2addr",            "12x",  0],
		[0xC9, "div-float/2addr",            "12x",  0],
		[0xCA, "rem-float/2addr",            "12x",  0],
		[0xCB, "add-double/2addr",           "12x",  0],
		[0xCC, "sub-double/2addr",           "12x",  0],
		[0xCD, "mul-double/2addr",           "12x",  0],
		[0xCE, "div-double/2addr",           "12x",  0],
		[0xCF, "rem-double/2addr",           "12x",  0],
		[0xD0, "add-int/lit16",              "22s",  0],
		[0xD1, "rsub-int",                   "22s",  0],
		[0xD2, "mul-int/lit16",              "22s",  0],
		[0xD3, "div-int/lit16",              "22s",  0],
		[0xD4, "rem-int/lit16",              "22s",  0],
		[0xD5, "and-int/lit16",              "22s",  0],
		[0xD6, "or-int/lit16",               "22s",  0],
		[0xD7, "xor-int/lit16",              "22s",  0],
		[0xD8, "add-int/lit8",               "22b",  0],
		[0xD9, "rsub-int/lit8",              "22b",  0],
		[0xDA, "mul-int/lit8",               "22b",  0],
		[0xDB, "div-int/lit8",               "22b",  0],
		[0xDC, "rem-int/lit8",               "22b",  0],
		[0xDD, "and-int/lit8",               "22b",  0],
		[0xDE, "or-int/lit8",                "22b",  0],
		[0xDF, "xor-int/lit8",               "22b",  0],
		[0xE0, "shl-int/lit8",               "22b",  0],
		[0xE1, "shr-int/lit8",               "22b",  0],
		[0xE2, "ushr-int/lit8",              "22b",  0],
		[0xE3, "iget-volatile",              "22c",  3],
		[0xE4, "iput-volatile",              "22c",  3],
		[0xE5, "sget-volatile",              "21c",  3],
		[0xE6, "sput-volatile",              "21c",  3],
		[0xE7, "iget-object-volatile",       "22c",  3],
		[0xE8, "iget-wide-volatile",         "22c",  3],
		[0xE9, "iput-wide-volatile",         "22c",  3],
		[0xEA, "sget-wide-volatile",         "21c",  3],
		[0xEB, "sput-wide-volatile",         "21c",  3],
		[0xEE, "execute-inline",             "35ms", 0],
		[0xEF, "execute-inline/range",       "3rms", 0],
		[0xF0, "invoke-direct-empty",        "35s",  4],
		[0xF2, "iget-quick",                 "22cs", 0],
		[0xF3, "iget-wide-quick",            "22cs", 0],
		[0xF4, "iget-object-quick",          "22cs", 0],
		[0xF5, "iput-quick",                 "22cs", 0],
		[0xF6, "iput-wide-quick",            "22cs", 0],
		[0xF7, "iput-object-quick",          "22cs", 0],
		[0xF8, "invoke-virtual-quick",       "35ms", 0],
		[0xF9, "invoke-virtual-quick/range", "3rms", 0],
		[0xFA, "invoke-super-quick",         "35ms", 0],
		[0xFB, "invoke-super-quick/range",   "3rms", 0],
		[0xFC, "iput-object-volatile",       "22c",  3],
		[0xFD, "sget-object-volatile",       "21c",  3],
		[0xFE, "sput-object-volatile",       "21c",  3]
	);
	my $opcode   = get_byte ($buffer, $offs);
	my $operand1 = get_byte ($buffer, $offs + 1);
	my $operand2;
	my $operand3;
	my $str;
	my $type_str;
	my $type_name;
	my $field_name;
	my $method_name;
	my $low_nibble  = $operand1 & 0x0F;
	my $high_nibble = ($operand1 & 0xF0) >> 4;
	my $mnemonic = "unknown";
	my $format   = "10x";
	my $ref_type = 0;
	$class_crc->add ($opcode);
	$class_crc->add ($operand1);
	for my $row (@opcodes)
	{
		if ($opcode == @$row [0])
		{
			$mnemonic = @$row [1];
			$format   = @$row [2];
			$ref_type = @$row [3];
			last;
		}
	}
	printf ("\t\t\t\t\t\t\t%02X %02X", $opcode, $operand1) if ($verbose);
	given ($format)
	{
		when "10t"
		{
			printf ("\t\t| %s\t.%+d\n", $mnemonic, unpack ('c', pack ('C', $operand1))) if ($verbose);
			return 2;
		}
		when "10x"
		{
			if ($opcode == 0x00)
			{
				given ($operand1)
				{
					when 0x01
					{
						my $size = get_word ($buffer, $offs + 2);
						my $first_key = get_dword ($buffer, $offs + 4);
						$class_crc->add ($size);
						$class_crc->add ($first_key);
						my $target;
						if ($verbose)
						{
							printf ("\t\t; packed-switch data:\n");
							printf ("\t\t\t\t\t\t\t%04X\t\t; size\t%d\n", $size, $size);
							printf ("\t\t\t\t\t\t\t%08X\t; first key\t%ld\n", $first_key, $first_key);
						}
						for (my $i = 0; $i < $size; $i++)
						{
							$target = get_dword ($buffer, $offs + 8 + $i * 4);
							printf ("\t\t\t\t\t\t\t%08X\t; target_%d\t%ld\n", $target, $i, unpack ('l', pack ('L', $target))) if ($verbose);
						}
						return $size * 4 + 8;
					}
					when 0x02
					{
						my $size = get_word ($buffer, $offs + 2);
						my $key;
						my $target;
						$class_crc->add ($size);
						if ($verbose)
						{
							printf ("\t\t; sparse-switch data:\n");
							printf ("\t\t\t\t\t\t\t%04X\t\t; size\t%d\n", $size, $size);
						}
						for (my $i = 0; $i < $size; $i++)
						{
							$key = get_dword ($buffer, $offs + 4 + $i * 4);
							$class_crc->add ($key);
							printf ("\t\t\t\t\t\t\t%08X\t; key_%d\t%ld\n", $key, $i, $key) if ($verbose);
						}
						for (my $i = 0; $i < $size; $i++)
						{
							$target = get_dword ($buffer, $offs + 4 + $i * 4 + 2);
							printf ("\t\t\t\t\t\t\t%08X\t; target_%d\t%ld\n", $target, $i, unpack ('l', pack ('L', $target))) if ($verbose);
						}
						return $size * 8 + 4;
					}
					when 0x03
					{
						my $el_size = get_word ($buffer, $offs + 2);
						my $size = get_dword ($buffer, $offs + 4);
						my $el_byte;
						my $element;
						$class_crc->add ($el_size);
						$class_crc->add ($size);
						if ($verbose)
						{
							printf ("\t\t; fill-array-data data:\n");
							printf ("\t\t\t\t\t\t\t%04X\t\t; element_width\t%d\n", $el_size, $el_size);
							printf ("\t\t\t\t\t\t\t%08X\t; size\t%ld\n", $size, $size);
						}
						for (my $i = 0; $i < $size; $i++)
						{
							$element = substr ($buffer, $offs + 8 + $i * $el_size, $el_size);
							$class_crc->add ($element);
							if ($verbose)
							{
								printf ("\t\t\t\t\t\t\t");
								for (my $j = 0; $j < $el_size; $j++)
								{
									printf ("%02X", ord (substr ($element, $j, 1)));
									printf (" ") if ($j + 1 < $el_size);
								}
								printf ("\t; element_%d\n", $i);
							}
						}
						my $ret_val = $size * $el_size + 8;
						$ret_val++ if ($ret_val & 1);
						return $ret_val;
					}
					default
					{
						printf ("\t\t| %s\n", $mnemonic) if ($verbose);
						return 2;
					}
				}
			}
			else
			{
				printf ("\t\t| %s\n", $mnemonic) if ($verbose);
				return 2;
			}
		}
		when "11n"
		{
			printf ("\t\t| %s\tv%d, #%d\n", $mnemonic, $low_nibble, $high_nibble) if ($verbose);
			return 2;
		}
		when "11x"
		{
			printf ("\t\t| %s\tv%d\n", $mnemonic, $operand1) if ($verbose);
			return 2;
		}
		when "12x"
		{
			printf ("\t\t| %s\tv%d, v%d\n", $mnemonic, $low_nibble, $high_nibble) if ($verbose);
			return 2;
		}
		when "20t"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %04X\t| %s\t.%+d\n", $operand2, $mnemonic, unpack ('s', pack ('S', $operand2))) if ($verbose);
			return 4;
		}
		when "21c"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			printf (" %04X\t| %s\tv%d, ", $operand2, $mnemonic, $operand1) if ($verbose);
			given ($ref_type)
			{
				when 1
				{
					#$str = get_string_slow ($buffer, $operand2, $string_offset);
					$str = get_string_fast ($strings, $operand2);
					$class_crc->add ($str);
					$str =~ s/\"/\\\"/g;
					printf ("string@%04X\t; \"%s\"", $operand2, $str) if ($verbose);
				}
				when 2
				{
					#$type_name = get_type_slow ($buffer, $operand2, $type_offs, $string_offset);
					$type_name = get_type_fast ($types, $operand2);
					$class_crc->add ($type_name);
					printf ("type@%04X\t; %s", $operand2, $type_name) if ($verbose);
				}
				when 3
				{
					#$field_name = get_field_slow ($buffer, $field_offs, $type_offs, $string_offset, $operand2);
					$field_name = get_field_fast ($fields, $operand2);
					$class_crc->add ($field_name);
					printf ("field@%04X\t; %s", $operand2, $field_name) if ($verbose);
				}
			}
			printf ("\n") if ($verbose);
			return 4;
		}
		when "21h"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			$str = "0000";
			$str .= $str if ($opcode == 0x19);
			printf (" %04X\t| %s\tv%d, #+0x%04X%s\n", $operand2, $mnemonic, $operand1, $operand2, $str) if ($verbose);
			return 4;
		}
		when "21s"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %04X\t| %s\tv%d, #%d\n", $operand2, $mnemonic, $operand1, unpack ('s', pack ('S', $operand2))) if ($verbose);
			return 4;
		}
		when "21t"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %04X\t| %s\tv%d, .%+d\n", $operand2, $mnemonic, $operand1, unpack ('s', pack ('S', $operand2))) if ($verbose);
			return 4;
		}
		when "22b"
		{
			$operand2 = get_byte ($buffer, $offs + 2);
			$operand3 = get_byte ($buffer, $offs + 3);
			$class_crc->add ($operand2);
			$class_crc->add ($operand3);
			printf (" %02X%02X\t| %s\tv%d, v%d, #%d\n", $operand2, $operand3, $mnemonic, $operand1, $operand2, unpack ('c', pack ('C', $operand3))) if ($verbose);
			return 4;
		}
		when "22c"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			if ($ref_type == 2)
			{
				$type_str = "type";
				#$type_name = get_type_slow ($buffer, $operand2, $type_offs, $string_offset);
				$type_name = get_type_fast ($types, $operand2);
			}
			else
			{
				$type_str = "field";
				#$type_name = get_field_slow ($buffer, $field_offs, $type_offs, $string_offset, $operand2);
				$type_name = get_field_fast ($fields, $operand2);
			}
			$class_crc->add ($type_str);
			$class_crc->add ($type_name);
			printf (" %04X\t| %s\tv%d, v%d, %s@%04X\t; %s\n", $operand2, $mnemonic, $low_nibble, $high_nibble, $type_str, $operand2, $type_name) if ($verbose);
			return 4;
		}
		when "22cs"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			#$field_name = get_field_slow ($buffer, $field_offs, $type_offs, $string_offset, $operand2);
			$field_name = get_field_fast ($fields, $operand2);
			$class_crc->add ($field_name);
			printf (" %04X\t| %s\tv%d, v%d, field@%04X\t; %s\n", $operand2, $mnemonic, $low_nibble, $high_nibble, $operand2, $field_name) if ($verbose);
			return 4;
		}
		when "22s"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %04X\t| %s\tv%d, v%d, #%d\n", $operand2, $mnemonic, $low_nibble, $high_nibble, unpack ('s', pack ('S', $operand2))) if ($verbose);
			return 4;
		}
		when "22t"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %04X\t| %s\tv%d, v%d, .%+d\n", $operand2, $mnemonic, $low_nibble, $high_nibble, unpack ('s', pack ('S', $operand2))) if ($verbose);
			return 4;
		}
		when "22x"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %04X\t| %s\tv%d, v%d\n", $operand2, $mnemonic, $operand1, $operand2) if ($verbose);
			return 4;
		}
		when "23x"
		{
			$operand2 = get_byte ($buffer, $offs + 2);
			$operand3 = get_byte ($buffer, $offs + 3);
			$class_crc->add ($operand2);
			$class_crc->add ($operand3);
			printf (" %02X%02X\t| %s\tv%d, v%d, v%d\n", $operand2, $operand3, $mnemonic, $operand1, $operand2, $operand3) if ($verbose);
			return 4;
		}
		when "30t"
		{
			$operand2 = unpack ('l', substr ($buffer, $offs + 2, 4));
			$class_crc->add ($operand2);
			printf (" %08X\t| %s\t.%+ld\n", $operand2, $mnemonic, $operand2) if ($verbose);
			return 6;
		}
		when "31c"
		{
			$operand2 = get_dword ($buffer, $offs + 2);
			#$str = get_string_slow ($buffer, $operand2, $string_offset);
			$str = get_string_fast ($strings, $operand2);
			$class_crc->add ($str);
			$str =~ s/\"/\\\"/g;
			printf (" %08X\t| %s\tv%d, string@%08X\t; %s\n", $operand2, $mnemonic, $operand1, $str) if ($verbose);
			return 6;
		}
		when "31i"
		{
			$operand2 = get_dword ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %08X\t| %s\tv%d, #%d\t; 0x08X\n", $operand2, $mnemonic, $operand1, unpack ('l', pack ('L', $operand2)), unpack ('l', pack ('L', $operand2))) if ($verbose);
			return 6;
		}
		when "31t"
		{
			$operand2 = get_dword ($buffer, $offs + 2);
			$class_crc->add ($operand2);
			printf (" %08X\t| %s\tv%d, %ld\n", $operand2, $mnemonic, $operand1, unpack ('l', pack ('L', $operand2))) if ($verbose);
			return 6;
		}
		when "32x"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$operand3 = get_word ($buffer, $offs + 4);
			$class_crc->add ($operand2);
			$class_crc->add ($operand3);
			printf (" %04X %04X\t| %s\tv%d, v%d\n", $operand2, $operand3, $mnemonic, $operand2, $operand3) if ($verbose);
			return 6;
		}
		when ["35c", "35s"]
		{
			$operand2 = get_word ($buffer, $offs + 2);
			if ($ref_type == 2)
			{
				$type_str = "type";
				#$type_name = get_type_slow ($buffer, $operand2, $type_offs, $string_offset);
				$type_name = get_type_fast ($types, $operand2);
			}
			else
			{
				$type_str = "method";
				#$type_name = get_method_slow ($buffer, $method_offs, $proto_offs, $type_offs, $string_offset, $operand2);
				$type_name = get_method_fast ($methods, $operand2);
			}
			$class_crc->add ($type_str);
			$class_crc->add ($type_name);
			my $last_reg = -1;
			$last_reg = $low_nibble if ((($high_nibble % 4) == 1) && ($high_nibble > 1));
			my $num_words = int ($high_nibble / 4);
			$num_words++ if ($high_nibble < 4);
			if ($verbose)
			{
				printf (" %04X", $operand2);
				for (my $i = 0; $i < $num_words; $i++)
				{
					$operand3 = get_word ($buffer, $offs + 4 + $i * 2);
					printf (" %04X", $operand3);
				}
				printf ("\t| %s\t{", $mnemonic);
			}
			my $num_regs = 0;
			for (my $i = 0; $i < $num_words; $i++)
			{
				$operand3 = get_word ($buffer, $offs + 4 + $i * 2);
				$class_crc->add ($operand3);
				if ($verbose)
				{
					for (my $j = 0; $j < 4; $j++)
					{
						printf ("v%d", $operand3 & 0x000F);
						printf (", ") if ($num_regs + 1 < $high_nibble);
						$operand3 >>= 4;
						$num_regs++;
						last if ($num_regs >= $high_nibble);
					}
					printf ("v%d", $last_reg) if ($last_reg >= 0);
					printf ("}, %s@%04X\t; %s\n", $type_str, $operand2, $type_name);
				}
			}
			return $num_words * 2 + 4;
		}
		when "35ms"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			my $last_reg = -1;
			$last_reg = $low_nibble if ((($high_nibble % 4) == 1) && ($high_nibble > 1));
			my $num_words = int ($high_nibble / 4);
			$num_words++ if ($high_nibble < 4);
			if ($verbose)
			{
				printf (" %04X", $operand2);
				for (my $i = 0; $i < $num_words; $i++)
				{
					$operand3 = get_word ($buffer, $offs + 4 + $i * 2);
					printf (" %04X", $operand3);
				}
				printf ("\t| %s\t{", $mnemonic);
			}
			my $num_regs = 0;
			for (my $i = 0; $i < $num_words; $i++)
			{
				$operand3 = get_word ($buffer, $offs + 4 + $i * 2);
				$class_crc->add ($operand3);
				if ($verbose)
				{
					for (my $j = 0; $j < 4; $j++)
					{
						printf ("v%d", $operand3 & 0x000F);
						printf (", ") if ($num_regs + 1 < $high_nibble);
						$operand3 >>= 4;
						$num_regs++;
						last if ($num_regs >= $high_nibble);
					}
					printf ("v%d", $last_reg) if ($last_reg >= 0);
					printf ("}, [%04X]\n", $type_str, $operand2);
				}
			}
			return $num_words * 2 + 4;
		}
		when "3rc"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$operand3 = get_word ($buffer, $offs + 4);
			if ($ref_type == 2)
			{
				$type_str = "type";
				#$type_name = get_type_slow ($buffer, $operand2, $type_offs, $string_offset);
				$type_name = get_type_fast ($types, $operand2);
			}
			else
			{
				$type_str = "method";
				#$type_name = get_method_slow ($buffer, $method_offs, $proto_offs, $type_offs, $string_offset, $operand2);
				$type_name = get_method_fast ($methods, $operand2);
			}
			$class_crc->add ($type_str);
			$class_crc->add ($type_name);
			if ($verbose)
			{
				printf (" %04X %04X\t| %s\t{", $operand2, $operand3, $mnemonic);
				my $reg_num = $operand3;
				for (my $i = 0; $i < $operand1; $i++)
				{
					printf ("v%d", $reg_num);
					printf (", ") if ($i + 1 < $operand1);
					$reg_num++;
				}
				printf ("}, %s@%04X\t; %s\n", $type_str, $operand2, $type_name);
			}
			return 6;
		}
		when "3rms"
		{
			$operand2 = get_word ($buffer, $offs + 2);
			$operand3 = get_word ($buffer, $offs + 4);
			$class_crc->add ($operand2);
			$class_crc->add ($operand3);
			if ($verbose)
			{
				printf (" %04X %04X\t| %s\t{", $operand2, $operand3, $mnemonic);
				my $start_reg = $operand3;
				for (my $i = 0; $i < $low_nibble; $i++)
				{
					printf ("v%d", $start_reg);
					printf (", ") if ($i + 1 < $low_nibble);
					$start_reg++;
				}
				printf ("}, [%04X]\n", $operand3);
			}
			return 6;
		}
		when "51l"
		{
			$operand2 = get_dword ($buffer, $offs + 2, 4);
			$operand3 = get_dword ($buffer, $offs + 6, 4);
			$class_crc->add ($operand2);
			$class_crc->add ($operand3);
			printf (" %08X%08X\t| %s\tv%d, #%ld%ld\n", $operand2, $operand3, $mnemonic, $operand1, $operand2, $operand3) if ($verbose);
			return 10;
		}
	}
}

sub dump_debug_info
{
	#my ($buffer, $dbg_offs, $type_ids_offs, $string_offset) = @_;
	my ($buffer, $dbg_offs, $strings, $types) = @_;
	my $offs = $dbg_offs;
	my $line_start;
	my $len;
	my $param_size;
	($len, $line_start) = get_uleb128 ($buffer, $offs);
	$offs += $len;
	($len, $param_size) = get_uleb128 ($buffer, $offs);
	$offs += $len;
	printf ("\t\t\t\t\t\t\tDbgLineStart:\t%d\n", $line_start);
	printf ("\t\t\t\t\t\t\tDbgNumParams:\t%d\n", $param_size);
	if ($param_size)
	{
		my $prm_idx;
		for (my $parameter = 0; $parameter < $param_size; $parameter++)
		{
			($len, $prm_idx) = get_uleb128 ($buffer, $offs);
			$offs += $len;
			$prm_idx--;
			#printf ("\t\t\t\t\t\t\t\tDbgParam $parameter:\t%s\n", get_long_type (get_string_slow ($buffer, $prm_idx, $string_offset)));
			printf ("\t\t\t\t\t\t\t\tDbgParam $parameter:\t%s\n", get_long_type (get_string_fast ($strings, $prm_idx)));
		}
	}
	my $opcode;
	printf ("\t\t\t\t\t\t\tDbgOpcodes:\n");
	do
	{
		$opcode = get_byte ($buffer, $offs);
		$offs++;
		given ($opcode)
		{
			when 0x00
			{
				printf ("\t\t\t\t\t\t\t\tDBG_END_SEQUENCE\n");
			}
			when 0x01
			{
				my $addr_diff;
				($len, $addr_diff) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				printf ("\t\t\t\t\t\t\t\tDBG_ADVANCE_PC (%d)\n", $addr_diff);
			}
			when 0x02
			{
				my $line_diff;
				($len, $line_diff) = get_sleb128 ($buffer, $offs);
				$offs += $len;
				printf ("\t\t\t\t\t\t\t\tDBG_ADVANCE_LINE (%d)\n", $line_diff);
			}
			when 0x03
			{
				my $reg_num;
				my $name_idx;
				my $type_idx;
				($len, $reg_num) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				($len, $name_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				$name_idx--;
				($len, $type_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				$type_idx--;
				#printf ("\t\t\t\t\t\t\t\tDBG_START_LOCAL (%d, %s, %s)\n", $reg_num, get_string_slow ($buffer, $name_idx, $string_offset), get_type_slow ($buffer, $type_idx, $type_ids_offs, $string_offset));
				printf ("\t\t\t\t\t\t\t\tDBG_START_LOCAL (%d, %s, %s)\n", $reg_num, get_string_fast ($strings, $name_idx), get_type_fast ($types, $type_idx));
			}
			when 0x04
			{
				my $reg_num;
				my $name_idx;
				my $type_idx;
				my $sig_idx;
				($len, $reg_num) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				($len, $name_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				$name_idx--;
				($len, $type_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				$type_idx--;
				($len, $sig_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				$sig_idx--;
				#printf ("\t\t\t\t\t\t\t\tDBG_START_LOCAL_EXTENDED (%d, %s, %s, %s)\n", $reg_num, get_string_slow ($buffer, $name_idx, $string_offset), get_type_slow ($buffer, $type_idx, $type_ids_offs, $string_offset), get_string_slow ($buffer, $sig_idx, $string_offset));
				printf ("\t\t\t\t\t\t\t\tDBG_START_LOCAL_EXTENDED (%d, %s, %s, %s)\n", $reg_num, get_string_fast ($strings, $name_idx), get_type_fast ($types, $type_idx), get_string_fast ($strings, $sig_idx));
			}
			when 0x05
			{
				my $reg_num;
				($len, $reg_num) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				printf ("\t\t\t\t\t\t\t\tDBG_END_LOCAL (%d)\n", $reg_num);
			}
			when 0x06
			{
				my $reg_num;
				($len, $reg_num) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				printf ("\t\t\t\t\t\t\t\tDBG_RESTART_LOCAL (%d)\n", $reg_num);
			}
			when 0x07
			{
				printf ("\t\t\t\t\t\t\t\tDBG_SET_PROLOGUE_END\n");
			}
			when 0x08
			{
				printf ("\t\t\t\t\t\t\t\tDBG_SET_EPILOGUE_BEGIN\n");
			}
			when 0x09
			{
				my $name_idx;
				($len, $name_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				$name_idx--;
				#printf ("\t\t\t\t\t\t\t\tDBG_SET_FILE (%s)\n", get_string_slow ($buffer, $name_idx, $string_offset));
				printf ("\t\t\t\t\t\t\t\tDBG_SET_FILE (%s)\n", get_string_fast ($strings, $name_idx));
			}
			default
			{
				printf ("\t\t\t\t\t\t\t\tDBG_SPECIAL (line + %d, address + %d)\n", ($opcode - 10) % 15 - 4, ($opcode - 10) / 15);
			}
		}
	}
	while ($opcode != 0x00);
}

sub dump_tries
{
	#my ($buffer, $code_offs, $code_size, $num_tries, $type_ids_offs, $string_offset, $class_crc) = @_;
	my ($buffer, $code_offs, $code_size, $num_tries, $types, $class_crc) = @_;
	my $offs = $code_offs + 16 + $code_size * 2;
	$offs += 2 if (($num_tries != 0) && (($code_size & 1) == 1));	# Padding!
	for (my $i = 0; $i < $num_tries; $i++)
	{
		my $instr_cnt = get_word  ($buffer, $offs + 4);
		$class_crc->add ($instr_cnt);
		if ($verbose)
		{
			printf ("\t\t\t\t\t\tTry entry $i:\n");
			printf ("\t\t\t\t\t\t\tStartAddr:\t%08X\n", get_dword ($buffer, $offs + 0));
			printf ("\t\t\t\t\t\t\tInstrCnt:\t%d\n",    $instr_cnt);
			printf ("\t\t\t\t\t\t\tHndlrOffs:\t%04X\n", get_word  ($buffer, $offs + 6));
		}
		$offs += 8;
	}
	if ($num_tries)
	{
		my $num_catch_lists;
		my $num_catches;
		my $len;
		($len, $num_catch_lists) = get_uleb128 ($buffer, $offs);
		$class_crc->add ($num_catch_lists);
		$offs += $len;
		printf ("\t\t\t\t\t\tNumCatchLists:\t%d\n", $num_catch_lists) if ($verbose);
		for (my $list = 0; $list < $num_catch_lists; $list++)
		{
			printf ("\t\t\t\t\t\t\tCatch list $list:\n") if ($verbose);
			my $sleb;
			$num_catches = 0;
			($len, $sleb) = get_sleb128 ($buffer, $offs);
			$class_crc->add ($sleb);
			$offs += $len;
			if ($sleb)
			{
				$num_catches = abs ($sleb);
				printf ("\t\t\t\t\t\t\t\tNumCatches:\t%d\n", $num_catches) if ($verbose);
				for (my $i = 0; $i < $num_catches; $i++)
				{
					my $type_idx;
					my $catch_addr;
					($len, $type_idx) = get_uleb128 ($buffer, $offs);
					$offs += $len;
					#my $type_name = get_type_slow ($buffer, $type_idx, $type_ids_offs, $string_offset);
					my $type_name = get_type_fast ($types, $type_idx);
					$class_crc->add ($type_name);
					($len, $catch_addr) = get_uleb128 ($buffer, $offs);
					$offs += $len;
					if ($verbose)
					{
						printf ("\t\t\t\t\t\t\t\tCatch $i:\n");
						printf ("\t\t\t\t\t\t\t\t\tType:\t%s\n",   $type_name);
						printf ("\t\t\t\t\t\t\t\t\tAddr:\t0x%X\n", $catch_addr);
					}
				}
			}
			if ($sleb <= 0)
			{
				my $catch_all;
				($len, $catch_all) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				printf ("\t\t\t\t\t\t\t\tCatchAllAddr:\t0x%X\n", $catch_all) if ($verbose);
			}
		}
	}
}

sub dump_code
{
	#my ($buffer, $code_offs, $type_ids_offs, $string_offset, $field_offs, $method_offs, $proto_offs, $class_crc) = @_;
	my ($buffer, $code_offs, $strings, $types, $fields, $methods, $class_crc) = @_;
	my $num_regs  = get_word  ($buffer, $code_offs +  0);
	my $in_args   = get_word  ($buffer, $code_offs +  2);
	my $out_args  = get_word  ($buffer, $code_offs +  4);
	my $num_tries = get_word  ($buffer, $code_offs +  6);
	my $dbg_offs  = get_dword ($buffer, $code_offs +  8);
	my $code_size = get_dword ($buffer, $code_offs + 12);
	$class_crc->add ($num_regs);
	$class_crc->add ($in_args);
	$class_crc->add ($out_args);
	$class_crc->add ($num_tries);
	$class_crc->add ($code_size);
	if ($verbose)
	{
		printf ("\t\t\t\t\t\tRegisters:\t%d\n",  $num_regs);
		printf ("\t\t\t\t\t\tInArgSize:\t%d\n",  $in_args);
		printf ("\t\t\t\t\t\tOutArgSize:\t%d\n", $out_args);
		printf ("\t\t\t\t\t\tNumTries:\t%d\n",   $num_tries);
		printf ("\t\t\t\t\t\tDbgOffs:\t%08X\n",  $dbg_offs);
	}
	if ($verbose)
	{
		#dump_debug_info ($buffer, $dbg_offs, $type_ids_offs, $string_offset) if ($dbg_offs);
		dump_debug_info ($buffer, $dbg_offs, $strings, $types) if ($dbg_offs);
		printf ("\t\t\t\t\t\tCodeSize:\t%08X\n", $code_size);
		printf ("\t\t\t\t\t\tCode:\n");
	}
	my $instr_offs = $code_offs + 16;
	my $i = 0;
	while ($i < $code_size * 2)
	{
		#$i += dump_instruction ($buffer, $instr_offs + $i, $string_offset, $type_ids_offs, $field_offs, $method_offs, $proto_offs, $class_crc);
		$i += dump_instruction ($buffer, $instr_offs + $i, $strings, $types, $fields, $methods, $class_crc);
	}
	#dump_tries ($buffer, $code_offs, $code_size, $num_tries, $type_ids_offs, $string_offset, $class_crc);
	dump_tries ($buffer, $code_offs, $code_size, $num_tries, $types, $class_crc);
}

sub dump_methods
{
	#my ($buffer, $offs, $method_offs, $proto_offs, $type_offs, $str_offs, $field_offs, $num_methods, $method_type, $class_crc) = @_;
	my ($buffer, $offs, $num_methods, $method_type, $strings, $types, $fields, $methods, $class_crc) = @_;
	my $method_id = 0;
	my $method_diff;
	my $method_name;
	my $len;
	my $flags;
	my $total_len = 0;
	for (my $method = 0; $method < $num_methods; $method++)
	{
		($len, $method_diff) = get_uleb128 ($buffer, $offs + $total_len);
		$method_id += $method_diff;
		$total_len += $len;
		($len, $flags) = get_uleb128 ($buffer, $offs + $total_len);
		$class_crc->add ($flags);
		$total_len += $len;
		my $code_offs;
		($len, $code_offs) = get_uleb128 ($buffer, $offs + $total_len);
		$total_len += $len;
		#$method_name = get_method_slow ($buffer, $method_offs, $proto_offs, $type_offs, $str_offs, $method_id);
		$method_name = get_method_fast ($methods, $method_id);
		$class_crc->add ($method_name);
		if ($verbose)
		{
			printf ("\t\t\t\t%s method %d:\t%s%s\n", $method_type, $method, get_access_flags ($flags, 1, 0), $method_name);
			printf ("\t\t\t\t\tMethod ID:\t%02X\n",   $method_id);
			printf ("\t\t\t\t\tAccess flags:\t%s\n",  get_access_flags ($flags, 0, 0));
			printf ("\t\t\t\t\tCode offset:\t%08X\n", $code_offs);
		}
		#dump_code ($buffer, $code_offs, $type_offs, $str_offs, $field_offs, $method_offs, $proto_offs, $class_crc) if ($code_offs);
		dump_code ($buffer, $code_offs, $strings, $types, $fields, $methods, $class_crc) if ($code_offs);
	}
	return $total_len;
}

sub dump_fields
{
	#my ($buffer, $offs, $field_offs, $type_offs, $str_offs, $num_fields, $field_type, $class_crc) = @_;
	my ($buffer, $offs, $num_fields, $field_type, $fields, $class_crc) = @_;
	my $field_id = 0;
	my $total_len = 0;
	my $len;
	my $flags;
	for (my $field = 0; $field < $num_fields; $field++)
	{
		my $field_diff;
		($len, $field_diff) = get_uleb128 ($buffer, $offs + $total_len);
		$field_id += $field_diff;
		$total_len += $len;
		($len, $flags) = get_uleb128 ($buffer, $offs + $total_len);
		$class_crc->add ($flags);
		$total_len += $len;
		#my $field_name = get_access_flags ($flags, 1, 1) . get_field_slow ($buffer, $field_offs, $type_offs, $str_offs, $field_id);
		my $field_name = get_access_flags ($flags, 1, 1) . get_field_fast ($fields, $field_id);
		$class_crc->add ($field_name);
		if ($verbose)
		{
			printf ("\t\t\t\t%s field %s:\t%s\n", $field_type, $field, $field_name);
			printf ("\t\t\t\t\tFieldID:\t%02X\n", $field_id);
			printf ("\t\t\t\t\tAccess flags:\t%s\n", get_access_flags ($flags, 0, 1));
		}
	}
	return $total_len;
}

sub decode_value
{
	my ($buffer, $offs, $value_type, $value_arg) = @_;
	my $val = get_byte ($buffer, $offs);
	$value_arg++;
	return $val if ($value_arg == 1);
	my $shift = 0;
	my $ret = 0;
	for (my $i = 0; $i < $value_arg; $i++)
	{
		$ret |= get_byte ($buffer, $offs + $i) << $shift;
		$shift += 8;
	}
	return $ret;
}

sub get_value
{
	#my ($buffer, $offs, $str_offs, $type_offs, $field_offs, $method_offs, $proto_offs, $value_type, $value_arg) = @_;
	my ($buffer, $offs, $value_type, $value_arg, $strings, $types, $fields, $methods) = @_;
	given ($value_type)
	{
		when 0x00
		{
			# Byte
			return (sprintf ("(byte) 0x%02X", get_byte ($buffer, $offs)), $value_arg + 1);
		}
		when 0x02
		{
			# Short
			return (sprintf ("(short) %d", decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x03
		{
			# Char
			return (sprintf ("(char) '%c'", decode_value ($buffer, $offs, $value_type, $value_arg) & 0xFF), $value_arg + 1);
		}
		when 0x04
		{
			# Int
			return (sprintf ("(int) %d", decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x06
		{
			# Long
			return (sprintf ("(long) %ld", decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x10
		{
			# Float
			return (sprintf ("(float) %f", decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x11
		{
			# Double
			return (sprintf ("(double) %f", decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x17
		{
			# String
			#return (sprintf ("(string) '%s'", get_string_slow ($buffer, decode_value ($buffer, $offs, $value_type, $value_arg), $str_offs)), $value_arg + 1);
			return (sprintf ("(string) '%s'", get_string_fast ($strings, decode_value ($buffer, $offs, $value_type, $value_arg))), $value_arg + 1);
		}
		when 0x18
		{
			# Type
			#return ("(type) " . get_type_slow ($buffer, decode_value ($buffer, $offs, $value_type, $value_arg), $type_offs, $str_offs), $value_arg + 1);
			return ("(type) " . get_type_fast ($types, decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x19
		{
			# Field
			#return ("(field) " . get_field_slow ($buffer, $field_offs, $type_offs, $str_offs, decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
			return ("(field) " . get_field_fast ($fields, decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x1A
		{
			# Method
			#return ("(method) " . get_method_slow ($buffer, $method_offs, $proto_offs, $type_offs, $str_offs, decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
			return ("(method) " . get_method_fast ($methods, decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x1B
		{
			# Enum
			#return ("(enum) " . get_field_slow ($buffer, $field_offs, $type_offs, $str_offs, decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
			return ("(enum) " . get_field_fast ($fields, decode_value ($buffer, $offs, $value_type, $value_arg)), $value_arg + 1);
		}
		when 0x1C
		{
			# Array
			my $num_elements;
			my $len;
			my $total_len = 0;
			my $ret_val = "";
			my $value;
			($len, $num_elements) = get_uleb128 ($buffer, $offs);
			$offs += $len;
			$total_len += $len;
			for (my $element = 0; $element < $num_elements; $element++)
			{
				my $value_type = get_byte ($buffer, $offs);
				my $value_arg = $value_type >> 5;
				$value_type &= 0x1F;
				$offs++;
				$total_len++;
				#($value, $len) = get_value ($buffer, $offs, $str_offs, $type_offs, $field_offs, $method_offs, $proto_offs, $value_type, $value_arg);
				($value, $len) = get_value ($buffer, $offs, $value_type, $value_arg, $strings, $types, $fields, $methods);
				$ret_val .= $value . ", " if ($element + 1 < $num_elements);
				$offs += $len;
				$total_len += $len;
			}
			return ("(array) [" . $ret_val . "]", $total_len);
		}
		when 0x1D
		{
			# Annotation
			my $num_elements;
			my $len;
			my $total_len = 0;
			my $ret_val = "(annotation) ";
			my $value;
			my $type_idx;
			($len, $type_idx) = get_uleb128 ($buffer, $offs);
			$offs += $len;
			$total_len += $len;
			#$ret_val .= get_type_slow ($buffer, $type_idx, $type_offs, $str_offs);
			$ret_val .= get_type_fast ($types, $type_idx);
			$ret_val .= " {";
			($len, $num_elements) = get_uleb128 ($buffer, $offs);
			$offs += $len;
			$total_len += $len;
			for (my $element = 0; $element < $num_elements; $element++)
			{
				my $name_idx;
				($len, $name_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				$total_len += $len;
				#my $value_name = get_string_slow ($buffer, $name_idx, $str_offset);
				my $value_name = get_string_fast ($strings, $name_idx);
				$ret_val .= $value_name;
				my $value_type = get_byte ($buffer, $offs);
				my $value_arg = $value_type >> 5;
				$value_type &= 0x1F;
				$offs++;
				$total_len++;
				#($value, $len) = get_value ($buffer, $offs, $str_offset, $type_offset, $field_offs, $method_offs, $proto_offs, $value_type, $value_arg);
				($value, $len) = get_value ($buffer, $offs, $value_type, $value_arg, $strings, $types, $fields, $methods);
				$offs += $len;
				$total_len += $len;
				$ret_val .= " = " . $value;
				$ret_val .= ", " if ($element + 1 < $num_elements);
			}
			return ($ret_val . "}", $total_len);
		}
		when 0x1E
		{
			# NULL
			return ("NULL", 0);
		}
		when 0x1F
		{
			# Boolean
			return ("(boolean) " . (($value_arg) ? "true" : "false"), 0);
		}
		default
		{
			return ("(error)", 0);
		}
	}
}

sub get_visibility
{
	my ($visibility) = @_;
	my @visibilities = (
		"VISIBILITY_BUILD",
		"VISIBILITY_RUNTIME",
		"VISIBILITY_SYSTEM"
	);
	if ($visibility <= $#visibilities)
	{
		return $visibilities [$visibility];
	}
	else
	{
		return "";
	}
}

sub dump_interfaces
{
	#my ($buffer, $interf_offs, $type_offset, $str_offset, $class_crc) = @_;
	my ($buffer, $interf_offs, $types, $class_crc) = @_;
	return unless ($interf_offs);
	my $offs = $interf_offs;
	my $num_interfaces = get_dword ($buffer, $offs);
	$class_crc->add ($num_interfaces);
	$offs += 4;
	printf ("\t\t\tNumInterfaces:\t$num_interfaces\n") if ($verbose);
	for (my $interface = 0; $interface < $num_interfaces; $interface++)
	{
		#my $interf_name = get_type_slow ($buffer, get_word ($buffer, $offs), $type_offset, $str_offset);
		my $interf_name = get_type_fast ($types, get_word ($buffer, $offs));
		$class_crc->add ($interf_name);
		printf ("\t\t\t\tInterface $interface:\t%s\n", $interf_name) if ($verbose);
		$offs += 2;
	}
}

sub dump_annotations
{
	#my ($buffer, $annotations_offs, $type_offset, $str_offset, $field_offs, $method_offs, $proto_offs, $class_crc) = @_;
	my ($buffer, $annotations_offs, $strings, $types, $fields, $methods, $class_crc) = @_;
	return unless ($annotations_offs);
	my $class_ann_offs = get_dword ($buffer, $annotations_offs);
	printf ("\t\t\tClassAnnOffs:\t%08X\n", $class_ann_offs) if ($verbose);
	if ($class_ann_offs > 0)
	{
		my $num_anns = get_dword ($buffer, $class_ann_offs);
		$class_crc->add ($num_anns);
		printf ("\t\t\t\tNumAnnotations:\t%08X\n", $num_anns) if ($verbose);
		my $offs;
		my $len;
		for (my $i = 0; $i < $num_anns; $i++)
		{
			my $ann_offs = get_dword ($buffer, $class_ann_offs + ($i + 1) * 4);
			my $visibility = get_byte ($buffer, $ann_offs);
			$class_crc->add ($visibility);
			$offs = $ann_offs + 1;
			my $type_idx;
			($len, $type_idx) = get_uleb128 ($buffer, $offs);
			$offs += $len;
			#my $ann_name = get_type_slow ($buffer, $type_idx, $type_offset, $str_offset);
			my $ann_name = get_type_fast ($types, $type_idx);
			$class_crc->add ($ann_name);
			my $num_elements;
			($len, $num_elements) = get_uleb128 ($buffer, $offs);
			$class_crc->add ($num_elements);
			$offs += $len;
			if ($verbose)
			{
				printf ("\t\t\t\t\tAnnotation %d:\t%s\n",     $i, $ann_name);
				printf ("\t\t\t\t\t\tAnnOffset:\t%08X\n",     $ann_offs);
				printf ("\t\t\t\t\t\tVisibility:\t%s (%d)\n", get_visibility ($visibility), $visibility);
				printf ("\t\t\t\t\t\tNumElems:\t%d\n",        $num_elements);
			}
			for (my $element = 0; $element < $num_elements; $element++)
			{
				my $name_idx;
				($len, $name_idx) = get_uleb128 ($buffer, $offs);
				$offs += $len;
				my $value_type = get_byte ($buffer, $offs);
				#$class_crc->add ($value_type);
				my $value_arg = $value_type >> 5;
				$value_type &= 0x1F;
				$offs++;
				my $value;
				#($value, $len) = get_value ($buffer, $offs, $str_offset, $type_offset, $field_offs, $method_offs, $proto_offs, $value_type, $value_arg);
				($value, $len) = get_value ($buffer, $offs, $value_type, $value_arg, $strings, $types, $fields, $methods);
				$class_crc->add ($value);
				$offs += $len;
				#my $value_name = get_string_slow ($buffer, $name_idx, $str_offset);
				my $value_name = get_string_fast ($strings, $name_idx);
				$class_crc->add ($value_name);
				printf ("\t\t\t\t\t\t\t%s = %s\n", $value_name, $value) if ($verbose);
			}
		}
	}
	my $num_fields      = get_dword ($buffer, $annotations_offs +  4);
	my $num_methods     = get_dword ($buffer, $annotations_offs +  8);
	my $num_param_lists = get_dword ($buffer, $annotations_offs + 12);
	$class_crc->add ($num_fields);
	$class_crc->add ($num_methods);
	$class_crc->add ($num_param_lists);
	if ($verbose)
	{
		printf ("\t\t\tNumFields:\t%08X\n",     $num_fields);
		printf ("\t\t\tNumMethods:\t%08X\n",    $num_methods);
		printf ("\t\t\tNumParamLists:\t%08X\n", $num_param_lists);
	}
}

sub dump_class_data
{
	#my ($buffer, $class_data_offs, $method_offs, $proto_offs, $type_offset, $str_offset, $field_offs, $class_crc) = @_;
	my ($buffer, $class_data_offs, $strings, $types, $fields, $methods, $class_crc) = @_;
	printf ("\t\tClassDataOffs:\t%08X\n", $class_data_offs) if ($verbose);
	return unless ($class_data_offs);
	my $offs = $class_data_offs;
	my $direct_methods;
	my $virtual_methods;
	my $static_fields;
	my $instance_fields;
	my $len;
	($len, $static_fields) = get_uleb128 ($buffer, $offs);
	$class_crc->add ($static_fields);
	printf ("\t\t\tNumStatFields:\t%d\n", $static_fields) if ($verbose);
	$offs += $len;
	($len, $instance_fields) = get_uleb128 ($buffer, $offs);
	$class_crc->add ($instance_fields);
	printf ("\t\t\tNumInstFields:\t%d\n", $instance_fields) if ($verbose);
	$offs += $len;
	($len, $direct_methods) = get_uleb128 ($buffer, $offs);
	$class_crc->add ($direct_methods);
	printf ("\t\t\tNumDirMethods:\t%d\n", $direct_methods) if ($verbose);
	$offs += $len;
	($len, $virtual_methods) = get_uleb128 ($buffer, $offs);
	$class_crc->add ($virtual_methods);
	printf ("\t\t\tNumVirMethods:\t%d\n", $virtual_methods) if ($verbose);
	$offs += $len;
	#$offs += dump_fields  ($buffer, $offs, $field_offs,  $type_offset, $str_offset, $static_fields,   "Static",   $class_crc);
	#$offs += dump_fields  ($buffer, $offs, $field_offs,  $type_offset, $str_offset, $instance_fields, "Instance", $class_crc);
	#$offs += dump_methods ($buffer, $offs, $method_offs, $proto_offs, $type_offset, $str_offset, $field_offs, $direct_methods,  "Direct",  $class_crc);
	#$offs += dump_methods ($buffer, $offs, $method_offs, $proto_offs, $type_offset, $str_offset, $field_offs, $virtual_methods, "Virtual", $class_crc);
	$offs += dump_fields  ($buffer, $offs, $static_fields,   "Static",   $fields, $class_crc);
	$offs += dump_fields  ($buffer, $offs, $instance_fields, "Instance", $fields, $class_crc);
	$offs += dump_methods ($buffer, $offs, $direct_methods,  "Direct",  $strings, $types, $fields, $methods, $class_crc);
	$offs += dump_methods ($buffer, $offs, $virtual_methods, "Virtual", $strings, $types, $fields, $methods, $class_crc);
}

sub dump_static_fields
{
	#my ($buffer, $static_data_offs, $str_offset, $type_offset, $field_offs, $method_offs, $proto_offs, $class_crc) = @_;
	my ($buffer, $static_data_offs, $strings, $types, $fields, $methods, $class_crc) = @_;
	printf ("\t\tStaticOffs:\t%08X\n", $static_data_offs) if ($verbose);
	return unless ($static_data_offs);
	my $offs = $static_data_offs;
	my $num_items;
	my $len;
	($len, $num_items) = get_uleb128 ($buffer, $offs);
	$class_crc->add ($num_items);
	$offs += $len;
	printf ("\t\t\tNumItems:\t%d\n", $num_items) if ($verbose);
	for (my $item = 0; $item < $num_items; $item++)
	{
		my $value_type = get_byte ($buffer, $offs);
		#$class_crc->add ($value_type);
		my $value_arg = $value_type >> 5;
		$value_type &= 0x1F;
		$offs++;
		my $value;
		#($value, $len) = get_value ($buffer, $offs, $str_offset, $type_offset, $field_offs, $method_offs, $proto_offs, $value_type, $value_arg);
		($value, $len) = get_value ($buffer, $offs, $value_type, $value_arg, $strings, $types, $fields, $methods);
		$class_crc->add ($value);
		$offs += $len;
		if ($verbose)
		{
			printf ("\t\t\t\tItem $item:\t%s\n",    $value);
			printf ("\t\t\t\t\tValueType:\t%02X\n", $value_type);
			printf ("\t\t\t\t\tValueArg:\t%02X\n",  $value_arg);
			printf ("\t\t\t\t\tTheValue:\t%s\n",    $value);
		}
	}
}

sub identify
{
	my ($file_crcs) = @_;
	my $name = "";
	my $detection = "";
	my $entry_size = 0;
	foreach my $entry (@database)
	{
		given (@$entry [1]->compare ($file_crcs))
		{
			when "disjoint"
			{
				# The sets have nothing in common.
			}
			when "proper subset"
			{
				# We have identified an entry. Keep looking for a bigger one.
				$detection = "Exact";
				if (@$entry [1]->size > $entry_size)
				{
					$name = @$entry [0];
					$entry_size = @$entry [1]->size;
				}
			}
			when "equal"
			{
				# We have identified an entry. There isn't going to be a better match.
				$detection = "Exact";
				$name = @$entry [0];
				last;
			}
			when "proper superset"
			{
				# We have identified remnants. Keep looking for a better match.
				if ($detection ne "Exact")
				{
					$detection = "Remnants";
					if (@$entry [1]->size > $entry_size)
					{
						$name = @$entry [0];
						$entry_size = @$entry [1]->size;
					}
				}
			}
			default
			{
				# Some classes in common but not a complete match. Keep looking.
				if ($detection ne "Exact")
				{
					$detection = "New variant";
					$name = @$entry [0];
					$name =~ s/\..+$//;
				}
			}
		}
	}
	if (($detection ne "") && ! $listcls)
	{
		if (! $silent)
		{
			printf ("\t") if ($idonly);
			printf ("Detected: %s (%s)\n", $name, $detection);
		}
		$identified = 1;
	}
	else
	{
		printf ("\n") if ($idonly);
	}
	printf ("\n") unless ($silent || $idonly);
}

sub process_file
{
	my ($filename) = @_;
	unless (-e $filename)
	{
		printf (STDERR "The file \'%s\' does not exist!\n", $filename);
		return;
	}
	Archive::Zip::setErrorHandler (sub { });
	my $zip = Archive::Zip->new ();
	my $buffer;
	my $md5;
	my $md5_postfix = "";
	if ($zip->read ($filename) == Archive::Zip::AZ_OK)
	{
		my $member = $zip->memberNamed ("classes.dex");
		return if (! $member);
		$buffer = $member->contents ();
		return if (lc (substr ($buffer, 0, 4)) ne "dex\n");
		if (! ($silent || $idonly))
		{
			$md5 = ($useMD5) ? Digest::MD5->new : Digest::SHA->new(256);
			open (APK, "< $filename");
			binmode (APK);
			$md5->addfile (*APK);
			$md5_postfix = " (" . uc ($md5->hexdigest) . "->";
			close (APK);
			$md5 = ($useMD5) ? Digest::MD5->new : Digest::SHA->new(256);
			$md5->add ($buffer);
			$md5_postfix .= uc ($md5->hexdigest);
		}
		$filename .= "->classes.dex";
	}
	else
	{
		my $filesize = -s $filename;
		return if ($filesize < 100);
		open (DEX, "< $filename");
		binmode (DEX);
		my $bytes_read = sysread (DEX, $buffer, 4);
		return if (($bytes_read < 4) || (lc ($buffer) ne "dex\n"));
		seek (DEX, 0, SEEK_SET);
		$bytes_read = sysread (DEX, $buffer, $filesize);
		return if ($bytes_read != $filesize);
		if (! ($silent || $idonly))
		{
			seek (DEX, 0, SEEK_SET);
			$md5 = ($useMD5) ? Digest::MD5->new : Digest::SHA->new(256);
			$md5->addfile (*DEX);
			$md5_postfix = " (" . uc ($md5->hexdigest);
		}
		close (DEX);
	}
	$md5_postfix .= ")" unless ($silent || $idonly);
	printf ("%s%s", $filename, $md5_postfix) unless ($silent);
	printf ("\n") unless ($idonly);
	my $adler32 = Digest::Adler32->new->add (substr ($buffer, 0x0C));
	my $sha     = Digest::SHA->new (1)->add (substr ($buffer, 0x20));
	my $a32     = $adler32->clone->digest;
	my $digest  = $sha->clone->digest;
	printf (STDERR "$filename\nAdler32 mismatch!\n\tNeeded:\t%08X\n\tFound:\t%08X\n", unpack ('L>', $a32), get_dword ($buffer, 0x08)) unless (get_dword ($buffer, 0x08) eq unpack ('L>', $a32));
	printf (STDERR "$filename\nSHA-1 mismatch!\n\tNeeded:\t%s\n\tFound:\t%s\n", uc (unpack ("H*", $digest)), uc (unpack ("H*", substr ($buffer, 0x0C, 20)))) unless (substr ($buffer, 0x0C, 20) eq $digest);
	my $file_crcs = Set::Scalar->new;
	my $map_offset  = get_dword ($buffer, 0x34);
	my $num_strings = get_dword ($buffer, 0x38);
	my $str_offset  = get_dword ($buffer, 0x3C);
	my $num_types   = get_dword ($buffer, 0x40);
	my $type_offset = get_dword ($buffer, 0x44);
	my $num_protos  = get_dword ($buffer, 0x48);
	my $proto_offs  = get_dword ($buffer, 0x4C);
	my $num_fields  = get_dword ($buffer, 0x50);
	my $field_offs  = get_dword ($buffer, 0x54);
	my $num_methods = get_dword ($buffer, 0x58);
	my $method_offs = get_dword ($buffer, 0x5C);
	my $num_classes = get_dword ($buffer, 0x60);
	my $class_offs  = get_dword ($buffer, 0x64);
	my @strings;
	my @types;
	my @fields;
	my @methods;
	unless ($listcls)
	{
		my $too_many;
		$too_many = (($num_strings > 1000) || ($num_types > 1000) || ($num_fields > 1000) || ($num_methods > 1000));
		printf (STDERR "Pre-processing the constant pools...") if ($too_many && ! ($silent || $idonly));
		for (my $i = 0; $i < $num_strings; $i++)
		{
			push (@strings, get_string_slow ($buffer, $i, $str_offset));
		}
		for (my $i = 0; $i < $num_types; $i++)
		{
			push (@types, get_type_medium ($buffer, $type_offset, \@strings, $i));
		}
		for (my $i = 0; $i < $num_fields; $i++)
		{
			push (@fields, get_field_medium ($buffer, $field_offs, $i, \@types, \@strings));
		}
		for (my $i = 0; $i < $num_methods; $i++)
		{
			push (@methods, get_method_medium ($buffer, $i, $method_offs, $proto_offs, \@types, \@strings));
		}
		printf (STDERR " done.\n") if ($too_many && ! ($silent || $idonly));
	}
	if ($verbose)
	{
		printf ("\tHeader:\n");
		printf ("\t\tMagic:\t\t\"%s\"\n",      substr ($buffer, 0, 3));
		printf ("\t\tVersion:\t%s\n",          substr ($buffer, 4, 3));
		printf ("\t\tChecksum:\t%s\n",         uc ($adler32->hexdigest));
		printf ("\t\tSHA-1:\t\t%s\n",          uc ($sha->hexdigest));
		printf ("\t\tFileSize:\t%d\n",         get_dword ($buffer, 0x20));
		printf ("\t\tHeaderSize:\t%08X\n",     get_dword ($buffer, 0x24));
		printf ("\t\tEndianness:\t%08X\n",     get_dword ($buffer, 0x28));
		printf ("\t\tLinkSize:\t%d\n",         get_dword ($buffer, 0x2C));
		printf ("\t\tLinkOffset:\t%08X\n",     get_dword ($buffer, 0x30));
		printf ("\t\tMapOffset:\t%08X\n",      $map_offset);
		printf ("\t\tNumStrings:\t%d\n",       $num_strings);
		printf ("\t\tStrIDOffset:\t%08X\n",    $str_offset);
		printf ("\t\tNumTypeIDs:\t%d\n",       $num_types);
		printf ("\t\tTypeIDsOffset:\t%08X\n",  $type_offset);
		printf ("\t\tNumProtoIDs:\t%d\n",      $num_protos);
		printf ("\t\tProtoIDsOffset:\t%08X\n", $proto_offs);
		printf ("\t\tNumFieldIDs:\t%d\n",      $num_fields);
		printf ("\t\tFieldIDsOffset:\t%08X\n", $field_offs);
		printf ("\t\tNumMethodIDs:\t%d\n",     $num_methods);
		printf ("\t\tMethodIDsOffs:\t%08X\n",  $method_offs);
		printf ("\t\tNumClasses:\t%d\n",       $num_classes);
		printf ("\t\tClassesDefOffs:\t%08X\n", $class_offs);
		printf ("\t\tDataSize:\t%d\n",         get_dword ($buffer, 0x68));
		printf ("\t\tDataOffset:\t%08X\n",     get_dword ($buffer, 0x6C));
	}
	my $offset = $class_offs;
	my $class_name;
	my $interf_offs;
	my $annotations_offs;
	my $class_data_offs;
	my $static_data_offs;
	for (my $class = 0; $class < $num_classes; $class++, $offset += 0x20)
	{
		my $class_crc = Digest::CRC->new (width => 32, init => 0xFFFFFFFF, xorout => 0x00000000, refout => 1, poly => 0x04C11DB7, refin => 1);
		$class_name = get_type_slow ($buffer, get_dword ($buffer, $offset), $type_offset, $str_offset);
		$class_crc->add ($class_name);
		if ($listcls)
		{
			printf ("\t%s\n", $class_name) unless (($class_name =~ m/\.R$/) || ($class_name =~ m/\.R\$/));
			next;
		}
		my $class_flags   = get_dword ($buffer, $offset +  4);
		$interf_offs      = get_dword ($buffer, $offset + 12);
		$class_data_offs  = get_dword ($buffer, $offset + 24);
		$annotations_offs = get_dword ($buffer, $offset + 20);
		$static_data_offs = get_dword ($buffer, $offset + 28);
		my $super_name = get_type_slow ($buffer, get_dword ($buffer, $offset +  8), $type_offset, $str_offset);
		$class_crc->add ($class_flags);
		$class_crc->add ($super_name);
		if ($verbose)
		{
			printf ("\tClass $class:\t%s%s\n",       get_access_flags ($class_flags, 1, 0), $class_name);
			printf ("\t\tTypeID:\t\t%08X (%s)\n",    get_dword ($buffer, $offset +  0), $class_name);
			printf ("\t\tAccessFlags:\t%s\n",        get_access_flags ($class_flags, 0, 0));
			printf ("\t\tSuperTypeID:\t%08X (%s)\n", get_dword ($buffer, $offset +  8), $super_name);
			printf ("\t\tInterfOffs:\t%08X\n",       $interf_offs);
		}
		#dump_interfaces ($buffer, $interf_offs, $type_offset, $str_offset, $class_crc);
		dump_interfaces ($buffer, $interf_offs, \@types, $class_crc);
		if ($verbose)
		{
			printf ("\t\tSrcFile:\t%08X (%s)\n", get_dword ($buffer, $offset + 16), get_string_slow ($buffer, get_dword ($buffer, $offset + 16), $str_offset));
			printf ("\t\tAnnotOffs:\t%08X\n", $annotations_offs);
		}
		#dump_annotations ($buffer, $annotations_offs, $type_offset, $str_offset, $field_offs, $method_offs, $proto_offs, $class_crc);
		#dump_class_data ($buffer, $class_data_offs, $method_offs, $proto_offs, $type_offset, $str_offset, $field_offs, $class_crc);
		#dump_static_fields ($buffer, $static_data_offs, $str_offset, $type_offset, $field_offs, $method_offs, $proto_offs, $class_crc);
		dump_annotations   ($buffer, $annotations_offs, \@strings, \@types, \@fields, \@methods, $class_crc);
		dump_class_data    ($buffer, $class_data_offs,  \@strings, \@types, \@fields, \@methods, $class_crc);
		dump_static_fields ($buffer, $static_data_offs, \@strings, \@types, \@fields, \@methods, $class_crc);
		if (($class_name !~ m/\.R$/) && ($class_name !~ m/\.R\$/))
		{
			my $crc = $class_crc->digest;
			printf ("\t%08X %s\n", $crc, $class_name) unless ($silent || $idonly);
			$file_crcs->insert ($crc);
		}
	}
	identify ($file_crcs);
}

__END__

=head1 NAME

dexid - Identifies exactly Android malware.

=head1 SYNOPSIS

dexid [-c|-k|-l|-s|-t|-u|-v][-d db...] APKfile|DEXfile|dir|@listfile...

 --help		this help message
 --version	display program version
 -c		only list the class names
 -k		check the database for duplicates
 -l		only list the contents of the database
 -m		use MD5 instead of SHA256 as file hashes (deprecated)
 -s		silent mode; only return error level
 -t		only display the identified malware names
 -u		update the database
 -v		verbose; dump classes.dex file in human-readable form
 -d db		specifies the name of the file to use as a database

=head1 DESCRIPTION

Parses and displays the contents (and identification data) of Android packages

=head1 AUTHOR

Vesselin Bontchev E<lt>F<vbontchev@yahoo.com>E<gt>.

=cut

__END__
:endofperl
