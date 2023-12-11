rule CN_Honker_syconfig
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file syconfig.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ff75353df77d610d3bccfbffb2c9dfa258b2fac9"
		os = "windows"
		filetype = "executable"

	strings:
		$s9 = "Hashq.CrackHost+FormUnit" fullword ascii

	condition:
		uint16(0)==0x0100 and filesize <18KB and all of them
}
