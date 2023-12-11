import "pe"

rule Enfal_Malware
{
	meta:
		description = "Detects a certain type of Enfal Malware"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/02/10"
		hash = "9639ec9aca4011b2724d8e7ddd13db19913e3e16"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "POWERPNT.exe" fullword ascii
		$s1 = "%APPDATA%\\Microsoft\\Windows\\" fullword ascii
		$s2 = "%HOMEPATH%" fullword ascii
		$s3 = "Server2008" fullword ascii
		$s4 = "Server2003" fullword ascii
		$s5 = "Server2003R2" fullword ascii
		$s6 = "Server2008R2" fullword ascii
		$s9 = "%HOMEDRIVE%" fullword ascii
		$s13 = "%ComSpec%" fullword ascii

	condition:
		all of them
}
