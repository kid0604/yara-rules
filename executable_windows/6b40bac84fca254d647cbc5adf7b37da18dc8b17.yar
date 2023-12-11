rule SUSP_Patcher_Keygen_Indicators_Jun15
{
	meta:
		description = "Sample from CN Honker Pentest Toolset"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e32f5de730e324fb386f97b6da9ba500cf3a4f8d"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "<description>Patch</description>" fullword ascii
		$s2 = "\\dup2patcher.dll" ascii
		$s3 = "load_patcher" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and all of them
}
