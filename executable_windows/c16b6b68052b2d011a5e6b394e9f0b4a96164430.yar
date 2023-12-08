rule Windows_Hacktool_PhysMem_b3fa382b
{
	meta:
		author = "Elastic Security"
		id = "b3fa382b-48a5-4004-92ad-bba0d42243ad"
		fingerprint = "81285d1d8bdb575cb3ebf7f2df2555544e3f1342917e207def00c358a77cd620"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.Hacktool.PhysMem"
		reference_sample = "88df37ede18bea511f1782c1a6c4915690b29591cf2c1bf5f52201fbbb4fa2b9"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Hacktool.PhysMem"
		filetype = "executable"

	strings:
		$str1 = "\\Phymemx64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
