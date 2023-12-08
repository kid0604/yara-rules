rule PP_CN_APT_ZeroT_3
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "ee2e2937128dac91a11e9bf55babc1a8387eb16cebe676142c885b2fc18669b2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/svchost.exe" fullword ascii
		$s2 = "RasTls.dll" fullword ascii
		$s3 = "20160620.htm" fullword ascii
		$s4 = "* $l&$" fullword ascii
		$s5 = "dfjhmh" fullword ascii
		$s6 = "/20160620.htm" fullword ascii

	condition:
		( uint16(0)==0x5449 and filesize <1000KB and 3 of them ) or ( all of them )
}
