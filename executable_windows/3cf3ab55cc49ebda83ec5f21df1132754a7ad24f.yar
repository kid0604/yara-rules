rule Hacktools_CN_Panda_tasksvr
{
	meta:
		description = "Disclosed hacktool set - file tasksvr.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Consys21.dll" fullword ascii
		$s4 = "360EntCall.exe" fullword wide
		$s15 = "Beijing1" fullword ascii

	condition:
		all of them
}
