rule OpCloudHopper_Malware_4
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		modified = "2023-01-06"
		hash1 = "ae6b45a92384f6e43672e617c53a44225e2944d66c1ffb074694526386074145"
		os = "windows"
		filetype = "executable"

	strings:
		$s6 = "operator \"\" " fullword ascii
		$s9 = "InvokeMainViaCRT" fullword ascii
		$s10 = ".?AVAES@@" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and all of them )
}
