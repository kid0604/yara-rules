import "pe"

rule Gh0st_alt_1 : RAT
{
	meta:
		description = "Gh0st"
		author = "botherder https://github.com/botherder"
		os = "windows"
		filetype = "executable"

	strings:
		$ = /(G)host/
		$ = /(i)nflate 1\.1\.4 Copyright 1995-2002 Mark Adler/
		$ = /(d)eflate 1\.1\.4 Copyright 1995-2002 Jean-loup Gailly/
		$ = /(%)s\\shell\\open\\command/
		$ = /(G)etClipboardData/
		$ = /(W)riteProcessMemory/
		$ = /(A)djustTokenPrivileges/
		$ = /(W)inSta0\\Default/
		$ = /(#)32770/
		$ = /(#)32771/
		$ = /(#)32772/
		$ = /(#)32774/

	condition:
		all of them
}
