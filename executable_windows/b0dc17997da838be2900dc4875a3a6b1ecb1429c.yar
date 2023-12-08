rule x64_klock
{
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "klock.dll" fullword ascii
		$s3 = "Erreur : le bureau courant (" fullword wide
		$s4 = "klock de mimikatz pour Windows" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <907KB and all of them
}
