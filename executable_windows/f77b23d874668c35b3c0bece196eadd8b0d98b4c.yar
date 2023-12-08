rule CN_Honker_SegmentWeapon
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SegmentWeapon.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "494ef20067a7ce2cc95260e4abc16fcfa7177fdf"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii
		$s1 = "http://www.nforange.com/inc/1.asp?" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
