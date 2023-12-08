rule InstGina
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5317fbc39508708534246ef4241e78da41a4f31c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "To Open Registry" fullword ascii
		$s4 = "I love Candy very much!!" ascii
		$s5 = "GinaDLL" fullword ascii

	condition:
		all of them
}
