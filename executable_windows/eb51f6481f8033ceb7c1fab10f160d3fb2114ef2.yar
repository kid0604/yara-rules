rule OpCloudHopper_Malware_9
{
	meta:
		description = "Detects malware from Operation Cloud Hopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
		date = "2017-04-03"
		hash1 = "f0002b912135bcee83f901715002514fdc89b5b8ed7585e07e482331e4a56c06"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "MsMpEng.exe" fullword ascii
		$op0 = { 2b c7 50 e8 22 83 ff ff ff b6 c0 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
