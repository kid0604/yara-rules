rule Windows_Hacktool_PhysMem_cc0978df
{
	meta:
		author = "Elastic Security"
		id = "cc0978df-153e-4421-8be8-37a0824133e2"
		fingerprint = "b94d5530dc3db4101b6ef06dc2421a10785f47bcb26d54f309a250a68699fa83"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Name: physmem.sys"
		threat_name = "Windows.Hacktool.PhysMem"
		reference_sample = "c299063e3eae8ddc15839767e83b9808fd43418dc5a1af7e4f44b97ba53fbd3d"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 70 00 68 00 79 00 73 00 6D 00 65 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}
