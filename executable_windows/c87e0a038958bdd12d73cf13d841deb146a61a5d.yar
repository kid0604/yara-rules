rule OSEditor
{
	meta:
		description = "Chinese Hacktool Set - file OSEditor.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "OSEditor.exe" fullword wide
		$s2 = "netsafe" wide
		$s3 = "OSC Editor" fullword wide
		$s4 = "GIF89" ascii
		$s5 = "Unlock" ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
