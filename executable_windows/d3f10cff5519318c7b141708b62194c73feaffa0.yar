rule cyclotron
{
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Device\\IDTProt" fullword wide
		$s2 = "IoDeleteSymbolicLink" fullword ascii
		$s3 = "\\??\\slIDTProt" fullword wide
		$s4 = "IoDeleteDevice" fullword ascii
		$s5 = "IoCreateSymbolicLink" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3KB and all of them
}
