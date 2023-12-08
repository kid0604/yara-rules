rule OpCloudHopper_Malware_1
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "27876dc5e6f746ff6003450eeea5e98de5d96cbcba9e4694dad94ca3e9fb1ddc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "zok]\\\\\\ZZYYY666564444" fullword ascii
		$s2 = "z{[ZZYUKKKIIGGGGGGGGGGGGG" fullword ascii
		$s3 = "EEECEEC" fullword ascii
		$s4 = "IIEFEE" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
