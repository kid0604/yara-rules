rule sig_238_letmein
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
		$s6 = "Error get users from server!" fullword ascii
		$s7 = "get in nt by name and null" fullword ascii
		$s16 = "get something from nt, hold by killusa." fullword ascii

	condition:
		all of them
}
