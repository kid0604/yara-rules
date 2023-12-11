rule PP_CN_APT_ZeroT_1
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "09061c603a32ac99b664f7434febfc8c1f9fd7b6469be289bb130a635a6c47c0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "suprise.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
