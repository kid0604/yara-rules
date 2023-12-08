import "pe"

rule IMPLANT_5_v3
{
	meta:
		description = "XTunnel Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$BYTES1 = { 0F AF C0 6? C0 07 00 00 00 2D 01 00 00 00 0F AF ?? 39 ?8 }
		$BYTES2 = { 0F AF C0 6? C0 07 48 0F AF ?? 39 ?8 }

	condition:
		any of them
}
