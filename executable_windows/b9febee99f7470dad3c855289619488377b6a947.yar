import "pe"

rule WPR_WindowsPasswordRecovery_EXE
{
	meta:
		description = "Windows Password Recovery - file wpr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "UuPipe" fullword ascii
		$x2 = "dbadllgl" fullword ascii
		$x3 = "UkVHSVNUUlkgTU9O" fullword ascii
		$x4 = "RklMRSBNT05JVE9SIC0gU1l" fullword ascii
		$s1 = "WPR.exe" fullword wide
		$s2 = "Windows Password Recovery" fullword wide
		$op0 = { 5f df 27 17 89 }
		$op1 = { 5f 00 00 f2 e5 cb 97 }
		$op2 = { e8 ed 00 f0 cc e4 00 a0 17 }

	condition:
		uint16(0)==0x5a4d and filesize <20000KB and (1 of ($x*) or all of ($s*) or all of ($op*))
}
