rule CN_APT_ZeroT_extracted_Go
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT  - file Go.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-04"
		modified = "2023-01-06"
		hash1 = "83ddc69fe0d3f3d2f46df7e72995d59511c1bfcca1a4e14c330cb71860b4806b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s\\cmd.exe /c %s\\Zlh.exe" fullword ascii
		$x2 = "\\BypassUAC.VS2010\\Release\\" ascii
		$s1 = "Zjdsf.exe" fullword ascii
		$s2 = "SS32prep.exe" fullword ascii
		$s3 = "windowsgrep.exe" fullword ascii
		$s4 = "Sysdug.exe" fullword ascii
		$s5 = "Proessz.exe" fullword ascii
		$s6 = "%s\\Zlh.exe" fullword ascii
		$s7 = "/C %s\\%s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 3 of ($s*))) or (7 of them )
}
