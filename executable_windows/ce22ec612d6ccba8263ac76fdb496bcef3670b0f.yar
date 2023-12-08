rule sig_238_iecv
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file iecv.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "6e6e75350a33f799039e7a024722cde463328b6d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Edit The Content Of Cookie " fullword wide
		$s3 = "Accessories\\wordpad.exe" fullword ascii
		$s4 = "gorillanation.com" fullword ascii
		$s5 = "Before editing the content of a cookie, you should close all windows of Internet" ascii
		$s12 = "http://nirsoft.cjb.net" fullword ascii

	condition:
		all of them
}
