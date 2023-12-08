rule Windows_VulnDriver_Biostar_e0b6cf55
{
	meta:
		author = "Elastic Security"
		id = "e0b6cf55-c97d-4799-88a6-30ab0e880b0b"
		fingerprint = "c38c456a008b847c42c45f824b125e7308b8aa41771d3db3d540690b13147abc"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.Biostar"
		reference_sample = "73327429c505d8c5fd690a8ec019ed4fd5a726b607cabe71509111c7bfe9fc7e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in Biostar drivers"
		filetype = "executable"

	strings:
		$str1 = "\\BS_RCIO.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
