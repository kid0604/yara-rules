rule Waterbear_12_Jun17
{
	meta:
		description = "Detects malware from Operation Waterbear"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/L9g9eR"
		date = "2017-06-23"
		hash1 = "15d9db2c90f56cd02be38e7088db8ec00fc603508ec888b4b85d60d970966585"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "O_PROXY" fullword ascii
		$s2 = "XMODIFY" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
