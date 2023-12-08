rule Kraken_Bot_Sample : bot
{
	meta:
		description = "Kraken Bot Sample - file inf.bin"
		author = "Florian Roth"
		reference = "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"
		date = "2015-05-07"
		hash = "798e9f43fc199269a3ec68980eb4d91eb195436d"
		score = 90
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "%s=?getname" fullword ascii
		$s4 = "&COMPUTER=^" fullword ascii
		$s5 = "xJWFwcGRhdGElAA=" fullword ascii
		$s8 = "JVdJTkRJUi" fullword ascii
		$s20 = "btcplug" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
