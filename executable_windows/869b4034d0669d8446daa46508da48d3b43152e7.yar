import "pe"

rule APT_Builder_PY_REDFLARE_2_alt_1
{
	meta:
		date = "2020-12-01"
		modified = "2020-12-01"
		md5 = "4410e95de247d7f1ab649aa640ee86fb"
		reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
		author = "FireEye"
		description = "Yara rule for detecting APT Builder PY REDFLARE 2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "<510sxxII"
		$s2 = "0x43,0x00,0x3a,0x00,0x5c,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,0x64,0x00,0x6f,0x00,"
		$s3 = "parsePluginOutput"

	condition:
		all of them and #s2==2
}
