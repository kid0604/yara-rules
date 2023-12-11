rule CGISscan_CGIScan
{
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Wang Products" fullword wide
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"

	condition:
		all of ($s*)
}
