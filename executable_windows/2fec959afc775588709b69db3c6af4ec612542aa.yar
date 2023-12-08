rule PoisonIvy_Sample_APT
{
	meta:
		description = "Detects a PoisonIvy APT malware group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b874b76ff7b281c8baa80e4a71fc9be514093c70"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "pidll.dll" fullword ascii
		$s1 = "sens32.dll" fullword wide
		$s3 = "FileDescription" fullword wide
		$s4 = "OriginalFilename" fullword wide
		$s5 = "ZwSetInformationProcess" fullword ascii
		$s9 = "Microsoft Media Device Service Provider" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <47KB and all of them
}
