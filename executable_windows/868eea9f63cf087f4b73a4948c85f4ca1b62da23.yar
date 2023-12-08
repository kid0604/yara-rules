import "pe"

rule WoolenGoldfish_Sample_1
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 60
		hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Cannot execute (%d)" fullword ascii
		$s16 = "SvcName" fullword ascii

	condition:
		all of them
}
