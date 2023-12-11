rule sig_238_concon
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file concon.com"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii

	condition:
		all of them
}
