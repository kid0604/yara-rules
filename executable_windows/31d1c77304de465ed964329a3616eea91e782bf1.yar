rule VUBrute_VUBrute
{
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
		$s1 = "http://ubrute.com" fullword ascii
		$s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
		$s14 = "error.txt" fullword ascii

	condition:
		all of them
}
