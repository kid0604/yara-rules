rule Dubnium_Sample_1
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
		os = "windows"
		filetype = "executable"

	strings:
		$key1 = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194" fullword ascii
		$key2 = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
