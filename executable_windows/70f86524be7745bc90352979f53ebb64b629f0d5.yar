rule Chinese_Hacktool_1014
{
	meta:
		description = "Detects a chinese hacktool with unknown use"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
		hash = "98c07a62f7f0842bcdbf941170f34990"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
		$s1 = "msctls_progress32" fullword wide
		$s2 = "Reply-To: %s" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "html htm htx asp" fullword ascii

	condition:
		all of them
}
