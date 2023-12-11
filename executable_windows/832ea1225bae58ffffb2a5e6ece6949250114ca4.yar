rule OpCloudHopper_Malware_10
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "5b4028728d8011a2003b7ce6b9ec663dd6a60b7adcc20e2125da318e2d9e13f4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "bakshell.EXE" fullword wide
		$s19 = "bakshell Applicazione MFC" fullword wide
		$op0 = { 83 c4 34 c3 57 8b ce e8 92 18 00 00 68 20 70 40 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
