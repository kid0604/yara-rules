rule jquery_code_su_multi
{
	meta:
		description = "Detects jQuery code with suspicious characters"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "=oQKpkyJ8dCK0lGbwNnLn42bpRXYj9GbENDft12bkBjM8V2Ypx2c8Rnbl52bw12bDlkUVVGZvNWZkZ0M85WavpGfsJXd8R1UPB1NywXZtFmb0N3box"

	condition:
		any of them
}
