rule OtherTools_servu_alt_1
{
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5c64e6879a9746a0d65226706e0edc7a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "MZKERNEL32.DLL" fullword ascii
		$s1 = "UpackByDwing@" fullword ascii
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "WriteFile" fullword ascii

	condition:
		uint32(0)==0x454b5a4d and $s0 at 0 and filesize <50KB and all of them
}
