rule MooreR_Port_Scanner
{
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Description|"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s7 = "DOWS\\SyMem32\\/o"

	condition:
		all of them
}
