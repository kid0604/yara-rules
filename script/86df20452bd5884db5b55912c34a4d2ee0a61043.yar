rule WaterPamola_webshell_eval
{
	meta:
		description = "WaterPamola eval webshell"
		author = "JPCERT/CC Incident Response Group"
		hash = "9fc3b3e59fbded4329a9401855d2576a1f2d76c429a0b9c8ea7c9752cd7e8378"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$encode1 = "IEBldmF"
		$encode2 = "F6ciddKTs="
		$encode3 = "CRfUE9TVF"
		$str1 = "@package Page"
		$str2 = " str_replace"
		$str3 = "$vbl"

	condition:
		uint32(0)==0x68703F3C and 4 of them
}
