rule Mal_Dropper_httpEXE_from_CAB : Dropper
{
	meta:
		description = "Detects a dropper from a CAB file mentioned in the article"
		author = "Florian Roth"
		reference = "https://goo.gl/13Wgy1"
		date = "2016-05-25"
		score = 60
		hash1 = "9e7e5f70c4b32a4d5e8c798c26671843e76bb4bd5967056a822e982ed36e047b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "029.Hdl" fullword ascii
		$s2 = "http.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and ( all of ($s*)))
}
