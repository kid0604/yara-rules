rule EternalRocks_svchost
{
	meta:
		description = "Detects EternalRocks Malware - file taskhost.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/stamparm/status/864865144748298242"
		date = "2017-05-18"
		hash1 = "589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WczTkaJphruMyBOQmGuNRtSNTLEs" fullword ascii
		$s2 = "svchost.taskhost.exe" fullword ascii
		$s3 = "ConfuserEx v" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 2 of them )
}
