rule Sphinx_Moth_nvcplex
{
	meta:
		description = "sphinx moth threat group file nvcplex.dat"
		author = "Kudelski Security - Nagravision SA"
		reference = "www.kudelskisecurity.com"
		date = "2015-08-06"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "mshtaex.exe" fullword wide
		$op0 = { 41 8b cc 44 89 6c 24 28 48 89 7c 24 20 ff 15 d3 }
		$op1 = { 48 3b 0d ad 8f 00 00 74 05 e8 ba f5 ff ff 48 8b }
		$op2 = { 8b ce e8 49 47 00 00 90 8b 43 04 89 05 93 f1 00 }

	condition:
		uint16(0)==0x5a4d and filesize <214KB and all of them
}
