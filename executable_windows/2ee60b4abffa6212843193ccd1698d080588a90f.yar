rule Windows_VulnDriver_Rtkio_5693e967
{
	meta:
		author = "Elastic Security"
		id = "5693e967-dbe4-457c-8b0c-404774871ac0"
		fingerprint = "4de76b2d42b523c4bfefeee8905e8f431168cb59e18049563f9942e97c276e46"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Name: rtkiow10x64.sys"
		threat_name = "Windows.VulnDriver.Rtkio"
		reference_sample = "ab8f2217e59319b88080e052782e559a706fa4fb7b8b708f709ff3617124da89"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 77 00 31 00 30 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}
