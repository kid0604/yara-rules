rule gozi_17386_canWell_js
{
	meta:
		description = "Gozi - file canWell.js"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "6bb867e53c46aa55a3ae92e425c6df91"
		os = "windows"
		filetype = "script"

	strings:
		$h1 = { 2F 2A 2A 0D 0A 09 57 68 6E 6C 64 47 68 0D 0A 2A 2F }
		$s1 = "reverseString" fullword
		$s2 = "123.com" fullword
		$s3 = "itsIt.db" fullword
		$s4 = "function ar(id)" fullword
		$s5 = "WScript.CreateObject" fullword

	condition:
		$h1 at 0 and filesize <1KB and all of ($s*)
}
