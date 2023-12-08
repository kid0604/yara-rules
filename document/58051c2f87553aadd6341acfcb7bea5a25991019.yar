rule CVE_2017_8759_WSDL_in_RTF
{
	meta:
		description = "Detects malicious RTF file related CVE-2017-8759"
		author = "Security Doggo @xdxdxdxdoa"
		reference = "https://twitter.com/xdxdxdxdoa/status/908665278199996416"
		date = "2017-09-15"
		os = "windows"
		filetype = "document"

	strings:
		$doc = "d0cf11e0a1b11ae1"
		$obj = "\\objupdate"
		$wsdl = "7700730064006c003d00" nocase
		$http1 = "68007400740070003a002f002f00" nocase
		$http2 = "680074007400700073003a002f002f00" nocase
		$http3 = "6600740070003a002f002f00" nocase

	condition:
		uint32be(0)==0x7B5C7274 and $obj and $doc and $wsdl and 1 of ($http*)
}
