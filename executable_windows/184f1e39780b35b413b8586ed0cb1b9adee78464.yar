rule Windows_VulnDriver_DirectIo_7bea6c8f
{
	meta:
		author = "Elastic Security"
		id = "7bea6c8f-7006-4994-be21-614e3cf1ec76"
		fingerprint = "6ad4cca6b8345825ef706d2e933508caf047a7d15a7f5b2f8d3d8a6f7c24b93d"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.DirectIo"
		reference_sample = "1dadd707c55413a16320dc70d2ca7784b94c6658331a753b3424ae696c5d93ea"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in VulnDriver DirectIo"
		filetype = "executable"

	strings:
		$str1 = "\\DirectIo.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
