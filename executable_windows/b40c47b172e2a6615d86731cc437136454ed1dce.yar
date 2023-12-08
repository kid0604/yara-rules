rule Unit78020_Malware_1
{
	meta:
		description = "Detects malware by Chinese APT PLA Unit 78020 - Specific Rule - msictl.exe"
		author = "Florian Roth"
		reference = "http://threatconnect.com/camerashy/?utm_campaign=CameraShy"
		date = "2015-09-24"
		hash = "a93d01f1cc2d18ced2f3b2b78319aadc112f611ab8911ae9e55e13557c1c791a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%ProgramFiles%\\Internet Explorer\\iexplore.exe" fullword ascii
		$s2 = "msictl.exe" fullword ascii
		$s3 = "127.0.0.1:8080" fullword ascii
		$s4 = "mshtml.dat" fullword ascii
		$s5 = "msisvc" fullword ascii
		$s6 = "NOKIAN95/WEB" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <160KB and 4 of them
}
