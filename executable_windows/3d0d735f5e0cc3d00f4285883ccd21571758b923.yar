rule Windows_VulnDriver_DBUtil_ffe07c79
{
	meta:
		author = "Elastic Security"
		id = "ffe07c79-d97b-43ba-92b9-206bb4c7bdd4"
		fingerprint = "16c22aba1e8c677cc22d3925dd7416a3c55c67271940289936a2cdc199a53798"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.DBUtil"
		reference_sample = "87e38e7aeaaaa96efe1a74f59fca8371de93544b7af22862eb0e574cec49c7c3"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in VulnDriver DBUtil"
		filetype = "executable"

	strings:
		$str1 = "\\DBUtilDrv2_32.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
