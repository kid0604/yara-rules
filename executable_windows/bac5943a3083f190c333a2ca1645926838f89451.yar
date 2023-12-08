rule CN_APT_ZeroT_extracted_Zlh
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT - file Zlh.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-04"
		hash1 = "711f0a635bbd6bf1a2890855d0bd51dff79021db45673541972fe6e1288f5705"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "nflogger.dll" fullword wide
		$s2 = "%s %d: CreateProcess('%s', '%s') failed. Windows error code is 0x%08x" fullword ascii
		$s3 = "_StartZlhh(): Executed \"%s\"" ascii
		$s4 = "Executable: '%s' (%s) %i" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them )
}
