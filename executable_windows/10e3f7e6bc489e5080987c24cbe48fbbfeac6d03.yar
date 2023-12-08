import "pe"

rule NHS_Strain_Wanna : NHS_Strain_Wanna
{
	meta:
		description = "Detection for worm-strain bundle of Wcry, DOublePulsar"
		MD5 = "db349b97c37d22f5ea1d1841e3c89eb4"
		SHA1 = "e889544aff85ffaf8b0d0da705105dee7c97fe26"
		SHA256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
		INFO = "Looks for specific offsets of c.wnry and t.wnry strings"
		os = "windows"
		filetype = "executable"

	strings:
		$cwnry = { 63 2e 77 6e 72 79 }
		$twnry = { 74 2e 77 6e 72 79 }

	condition:
		$cwnry at 262324 and $twnry at 267672 and $cwnry at 284970
}
