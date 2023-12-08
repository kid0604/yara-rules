rule HDRoot_Sample_Jul17_1
{
	meta:
		description = "Detects HDRoot samples"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Winnti HDRoot VT"
		date = "2017-07-07"
		hash1 = "6d2ad82f455becc8c830d000633a370857928c584246a7f41fe722cc46c0d113"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "gleupdate.dll" fullword ascii
		$s2 = "\\DosDevices\\%ws\\system32\\%ws" wide
		$s3 = "l\\Driver\\nsiproxy" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <60KB and 3 of them )
}
