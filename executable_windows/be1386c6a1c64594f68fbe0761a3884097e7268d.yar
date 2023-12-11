rule APT_CN_MAL_RedDelta_Shellcode_Loader_Oct20_1
{
	meta:
		description = "Detects Red Delta samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/JAMESWT_MHT/status/1316387482708119556"
		date = "2020-10-14"
		hash1 = "30b2bbce0ca4cb066721c94a64e2c37b7825dd72fc19c20eb0ab156bea0f8efc"
		hash2 = "42ed73b1d5cc49e09136ec05befabe0860002c97eb94e9bad145e4ea5b8be2e2"
		hash3 = "480a8c883006232361c5812af85de9799b1182f1b52145ccfced4fa21b6daafa"
		hash4 = "7ea7c6406c5a80d3c15511c4d97ec1e45813e9c58431f386710d0486c4898b98"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "InjectShellCode" ascii fullword
		$s1 = "DotNetLoader.exe" wide ascii fullword
		$s2 = "clipboardinject" ascii fullword
		$s3 = "download.php?raw=1" wide
		$s4 = "Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\Levint" wide
		$s5 = "FlashUpdate.exe" wide
		$s6 = "raw_cc_url" ascii fullword
		$op1 = { 48 8b 4c 24 78 48 89 01 e9 1a ff ff ff 48 8b 44 }
		$op2 = { ff ff 00 00 77 2a 8b 44 24 38 8b 8c 24 98 }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and $x1 or 3 of them
}
