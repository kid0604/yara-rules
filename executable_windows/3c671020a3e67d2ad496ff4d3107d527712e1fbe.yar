rule Windows_VulnDriver_GlckIo_39c4abd4
{
	meta:
		author = "Elastic Security"
		id = "39c4abd4-0c14-49e6-ab5c-edc260d28666"
		fingerprint = "80971a85f52d52dd80f1887b5b4fc2e101886e60b78b08ca9bb8f781db9f9751"
		creation_date = "2022-04-04"
		last_modified = "2022-08-30"
		threat_name = "Windows.VulnDriver.GlckIo"
		reference_sample = "3a5ec83fe670e5e23aef3afa0a7241053f5b6be5e6ca01766d6b5f9177183c25"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability driver GlckIo"
		filetype = "executable"

	strings:
		$str1 = "\\GLCKIO2.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and int16 ( uint32(0x3C)+0x18)==0x020b and $str1
}
