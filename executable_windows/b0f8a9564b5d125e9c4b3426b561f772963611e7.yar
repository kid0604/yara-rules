rule Windows_VulnDriver_Rtkio_b09af431
{
	meta:
		author = "Elastic Security"
		id = "b09af431-307b-40e2-bac5-5865c1ad54c8"
		fingerprint = "e62a497acc1ee04510aa42ca96c5265e16b3be665f99e7dfc09ecc38055aca5b"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Name: rtkiow8x64.sys"
		threat_name = "Windows.VulnDriver.Rtkio"
		reference_sample = "b205835b818d8a50903cf76936fcf8160060762725bd74a523320cfbd091c038"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 38 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}
