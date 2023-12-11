rule OpCloudHopper_Malware_2
{
	meta:
		description = "Detects Operation CloudHopper malware samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		modified = "2023-01-06"
		score = 90
		hash1 = "c1dbf481b2c3ba596b3542c7dc4e368f322d5c9950a78197a4ddbbaacbd07064"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "sERvEr.Dll" fullword ascii
		$x2 = "ToolbarF.dll" fullword wide
		$x3 = ".?AVCKeyLoggerManager@@" fullword ascii
		$x4 = "GH0STCZH" ascii
		$s1 = "%%SystemRoot%%\\System32\\svchost.exe -k \"%s\"" fullword wide
		$s2 = "rundll32.exe \"%s\", UnInstall /update %s" fullword wide
		$s3 = "\\Release\\Loader.pdb" ascii
		$s4 = "%s\\%x.dll" fullword wide
		$s5 = "Mozilla/4.0 (compatible)" fullword wide
		$s6 = "\\syslog.dat" wide
		$s7 = "NSOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
		$op1 = { 8d 34 17 8d 49 00 8a 14 0e 3a 14 29 75 05 41 3b }
		$op2 = { 83 e8 14 78 cf c1 e0 06 8b f8 8b c3 8a 08 84 c9 }
		$op3 = { 3b fb 7d 3f 8a 4d 14 8d 45 14 84 c9 74 1b 8a 14 }

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 3 of ($s*)) or all of ($op*)) or (6 of them )
}
