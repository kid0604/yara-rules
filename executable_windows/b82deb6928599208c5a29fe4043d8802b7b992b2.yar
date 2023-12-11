rule INDICATOR_TOOL_ExtPassword
{
	meta:
		author = "ditekSHen"
		description = "Detects ExtPassword External Drive Password Recovery"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "ExtPassword!" fullword wide
		$s2 = "GReading Chrome password file: %s" fullword wide
		$s3 = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%d" fullword wide
		$s4 = "2015-07-27 13:49:41 b8e92227a469de677a66da62e4361f099c0b79d0" ascii
		$s5 = "metadata WHERE id = 'password'" ascii
		$s6 = /Scanning\s(Credentials\sfolder|Credentials\sfolder|Firefox\sand\sother\sMozilla\sWeb\sbrowsers|Chromium-based\Web\browsers|Outlook\saccounts|Windows\sVault|dialup\/VPN\sitems|wireless\skeys|Windows\ssecurity\squestions|vault\spasswords)/ wide
		$s7 = "lhelp32Snapsho" fullword ascii
		$s8 = "SELECT origin_" fullword ascii
		$s9 = "password#Ck" fullword ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) and 3 of ($s*)) or 6 of ($s*)
}
