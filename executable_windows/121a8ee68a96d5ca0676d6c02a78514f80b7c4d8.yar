import "pe"

rule Equation_Kaspersky_SuspiciousString
{
	meta:
		description = "Equation Group Malware - suspicious string found in sample"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/17"
		score = 60
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$s1 = "i386\\DesertWinterDriver.pdb" fullword
		$s2 = "Performing UR-specific post-install..."
		$s3 = "Timeout waiting for the \"canInstallNow\" event from the implant-specific EXE!"
		$s4 = "STRAITSHOOTER30.exe"
		$s5 = "standalonegrok_2.1.1.1"
		$s6 = "c:\\users\\rmgree5\\"

	condition:
		($mz at 0) and filesize <500000 and all of ($s*)
}
