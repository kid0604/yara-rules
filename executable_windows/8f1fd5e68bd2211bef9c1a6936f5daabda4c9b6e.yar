rule Waterbear_10_Jun17
{
	meta:
		description = "Detects malware from Operation Waterbear"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/L9g9eR"
		date = "2017-06-23"
		hash1 = "3b1e67e0e86d912d7bc6dee5b0f801260350e8ce831c93c3e9cfe5a39e766f41"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ADVPACK32.DLL" fullword wide
		$s5 = "ADVPACK32" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
