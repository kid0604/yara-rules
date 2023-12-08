rule sig_238_Glass2k
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Portions Copyright (c) 1997-1999 Lee Hasiuk" fullword ascii
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" fullword ascii
		$s3 = "WINNT\\System32\\stdole2.tlb" fullword ascii
		$s4 = "Glass2k.exe" fullword wide
		$s7 = "NeoLite Executable File Compressor" fullword ascii

	condition:
		all of them
}
