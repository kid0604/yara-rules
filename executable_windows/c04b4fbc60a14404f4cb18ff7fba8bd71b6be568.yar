rule Windows_Hacktool_Mimikatz_71fe23d9
{
	meta:
		author = "Elastic Security"
		id = "71fe23d9-ee1a-47fb-a99f-2be2eb9ccb1a"
		fingerprint = "22b1f36e82e604fc3a80bb5abf87aef59957b1ceeb050eea3c9e85fb0b937db1"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Subject: Benjamin Delpy"
		threat_name = "Windows.Hacktool.Mimikatz"
		reference_sample = "856687718b208341e7caeea2d96da10f880f9b5a75736796a1158d4c8755f678"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}
