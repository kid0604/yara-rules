rule GoldenEyeRansomware_Dropper_MalformedZoomit
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/jp2SkT"
		date = "2016-12-06"
		hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
		$n1 = "Mark Russinovich" wide

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and $s1 and not $n1)
}
