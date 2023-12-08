rule Windows_VulnDriver_VBox_3315863f
{
	meta:
		author = "Elastic Security"
		id = "3315863f-668c-47ec-86c7-85d50c3b97d9"
		fingerprint = "b0aea1369943318246f1601f823c72f92a0155791661dadc4c854827c295e4bf"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Subject: innotek GmbH"
		threat_name = "Windows.VulnDriver.VBox"
		reference_sample = "42d926cfb3794f9b1e3cb397498696cb687f505e15feb9df11b419c49c9af498"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}
