rule OpCloudHopper_WmiDLL_inMemory
{
	meta:
		description = "Malware related to Operation Cloud Hopper - Page 25"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		date = "2017-04-07"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "wmi.dll 2>&1" ascii

	condition:
		all of them
}
