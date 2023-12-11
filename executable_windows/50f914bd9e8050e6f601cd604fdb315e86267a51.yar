rule Windows_Hacktool_LeiGod_3f5c98c4
{
	meta:
		author = "Elastic Security"
		id = "3f5c98c4-03ba-4919-90b0-604d3cb9361e"
		fingerprint = "883dcad7097ad5713c4f45ce2fc232c3c1e61cf9dfdc81a194124d5995a64c9e"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.Hacktool.LeiGod"
		reference_sample = "0c42fe45ffa9a9c36c87a7f01510a077da6340ffd86bf8509f02c6939da133c5"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows.Hacktool.LeiGod"
		filetype = "executable"

	strings:
		$str1 = "\\LgDCatcher.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
