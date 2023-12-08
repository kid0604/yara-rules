import "pe"

rule HKTL_shellpop_Perl
{
	meta:
		description = "Detects Shellpop Perl script"
		author = "Tobias Michalski"
		reference = "https://github.com/0x00-0x00/ShellPop"
		date = "2018-05-18"
		hash1 = "32c3e287969398a070adaad9b819ee9228174c9cb318d230331d33cda51314eb"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "perl -e 'use IO::Socket::INET;$|=1;my ($s,$r);" ascii
		$ = ";STDIN->fdopen(\\$c,r);$~->fdopen(\\$c,w);s" ascii

	condition:
		filesize <2KB and 1 of them
}
