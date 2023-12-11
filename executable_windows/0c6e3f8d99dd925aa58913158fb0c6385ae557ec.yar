rule OpCloudHopper_WindowXarBot
{
	meta:
		description = "Malware related to Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
		date = "2017-04-07"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Release\\WindowXarbot.pdb" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
