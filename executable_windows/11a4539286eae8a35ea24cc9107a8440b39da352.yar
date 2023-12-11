rule Windows_VulnDriver_Asrock_986d2d3c
{
	meta:
		author = "Elastic Security"
		id = "986d2d3c-96d1-4c74-a594-51c6df3b2896"
		fingerprint = "17a021c4130a41ca6714f2dd7f33c100ba61d6d2d4098a858f917ab49894b05b"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.Asrock"
		reference_sample = "3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability driver related to Asrock"
		filetype = "executable"

	strings:
		$str1 = "\\AsrDrv106.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
