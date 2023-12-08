rule OtherTools_servu
{
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		author = "Florian Roth"
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
		$s0 at 0 and filesize <50KB and all of them
}
