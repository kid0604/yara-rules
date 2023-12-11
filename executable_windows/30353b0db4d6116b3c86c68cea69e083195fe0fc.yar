rule Windows_VulnDriver_Rtkio_d595781e
{
	meta:
		author = "Elastic Security"
		id = "d595781e-67c1-47bf-a7ea-bb4a9ba33879"
		fingerprint = "efe0871703d5c146764c4a7ac9c80ae4e635dc6dd0e718e6ddc4c39b18ca9fdd"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Name: rtkio64.sys"
		threat_name = "Windows.VulnDriver.Rtkio"
		reference_sample = "4ed2d2c1b00e87b926fb58b4ea43d2db35e5912975f4400aa7bd9f8c239d08b7"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}
