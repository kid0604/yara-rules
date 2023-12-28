rule tick_daserf_1_5_not_mini
{
	meta:
		description = "Daserf malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "446e71e2b12758b4ceda27ba2233e464932cf9dc96daa758c4b221c8a433570f"
		os = "windows"
		filetype = "executable"

	strings:
		$user_agent = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; SV1)"
		$s1 = "Progman"
		$s3 = ".asp"
		$s4 = "DRIVE_" wide

	condition:
		all of them
}
