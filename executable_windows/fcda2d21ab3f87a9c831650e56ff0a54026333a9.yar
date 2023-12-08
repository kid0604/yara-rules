rule RedLeaves
{
	meta:
		description = "detect RedLeaves in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory block scan"
		reference = "https://blogs.jpcert.or.jp/en/2017/05/volatility-plugin-for-detecting-redleaves-malware.html"
		hash1 = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"
		os = "windows"
		filetype = "executable"

	strings:
		$v1 = "red_autumnal_leaves_dllmain.dll"
		$b1 = { FF FF 90 00 }

	condition:
		$v1 and $b1 at 0
}
