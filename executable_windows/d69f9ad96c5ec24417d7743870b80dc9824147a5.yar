rule QQ_zip_Folder_QQ
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file QQ.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "EMAIL:haoq@neusoft.com" fullword wide
		$s1 = "EMAIL:haoq@neusoft.com" fullword wide
		$s4 = "QQ2000b.exe" fullword wide
		$s5 = "haoq@neusoft.com" fullword ascii
		$s9 = "QQ2000b.exe" fullword ascii
		$s10 = "\\qq2000b.exe" fullword ascii
		$s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
		$s17 = "SOFTWARE\\HAOQIANG\\" fullword ascii

	condition:
		5 of them
}
