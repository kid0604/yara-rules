rule OpCloudHopper_Malware_6
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "aabebea87f211d47f72d662e2449009f83eac666d81b8629cf57219d0ce31af6"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "YDNCCOVZKXGRVQPOBRNXXQVNQYXBBCONCOQEGYELIRBEYOVODGXCOXTHXPCXNGUCHRVWKKZSYQMAOWWGHRSPRGSEUWYMEFZHRTHO" fullword ascii
		$s2 = "psychiatry.dat" fullword ascii
		$s3 = "meekness.lnk" fullword ascii
		$s4 = "SOFTWARE\\EGGORG" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
