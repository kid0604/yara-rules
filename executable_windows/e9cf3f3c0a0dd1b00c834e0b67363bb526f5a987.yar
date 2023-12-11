rule FourElementSword_ElevateDLL_2
{
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Elevate.dll" fullword ascii
		$s2 = "GetSomeF" fullword ascii
		$s3 = "GetNativeSystemInfo" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <25KB and $s1) or ( all of them )
}
