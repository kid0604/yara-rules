rule Windows_VulnDriver_DBUtil_852ba283
{
	meta:
		author = "Elastic Security"
		id = "852ba283-6a03-44b6-b7e2-b00d1b0586e4"
		fingerprint = "aec919dfea62a8ed01dde4e8c63fbfa9c2a9720c144668460c00f56171c8db25"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.DBUtil"
		reference_sample = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in DBUtil driver"
		filetype = "executable"

	strings:
		$str1 = "\\DBUtilDrv2_64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
