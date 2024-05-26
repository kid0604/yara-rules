import "math"

rule WEBSHELL_JSP_Generic_Encoded_Shell_alt_2
{
	meta:
		description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-07-05"
		hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
		hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
		hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
		id = "359949d7-1793-5e13-9fdc-fe995ae12117"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sj0 = /\{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
		$sj1 = /\{ ?99, 109, 100}/ wide ascii
		$sj2 = /\{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
		$sj3 = /\{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
		$sj4 = /\{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
		$sj5 = /\{ ?101, 120, 101, 99 }/ wide ascii
		$sj6 = /\{ ?103, 101, 116, 82, 117, 110/ wide ascii

	condition:
		filesize <300KB and any of ($sj*)
}
