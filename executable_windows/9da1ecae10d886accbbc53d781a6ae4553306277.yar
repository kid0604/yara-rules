rule Hacktools_CN_Http
{
	meta:
		description = "Disclosed hacktool set - file Http.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "RPCRT4.DLL" fullword ascii
		$s1 = "WNetAddConnection2A" fullword ascii
		$s2 = "NdrPointerBufferSize" fullword ascii
		$s3 = "_controlfp" fullword ascii

	condition:
		all of them and filesize <10KB
}
