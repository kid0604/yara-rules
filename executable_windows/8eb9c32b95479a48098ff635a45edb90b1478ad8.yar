rule Windows_Trojan_Trickbot_78a26074
{
	meta:
		author = "Elastic Security"
		id = "78a26074-dc4b-436d-8188-2a3cfdabf6db"
		fingerprint = "f0446c7e1a497b93720824f4a5b72f23f00d0ee9a1607bc0c1b097109ec132a8"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets psfin64.dll module containing point-of-sale recon functionality"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "8CD75FA8650EBCF0A6200283E474A081CC0BE57307E54909EE15F4D04621DDE0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "<moduleconfig><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"SetConf\" file=\"dpost\" period=\"14400\"/></a"
		$a2 = "Dpost servers unavailable" ascii fullword
		$a3 = "moduleconfig>" ascii fullword
		$a4 = "ALOHA found: %d" wide fullword
		$a5 = "BOH found: %d" wide fullword
		$a6 = "MICROS found: %d" wide fullword
		$a7 = "LANE found: %d" wide fullword
		$a8 = "RETAIL found: %d" wide fullword
		$a9 = "REG found: %d" wide fullword
		$a10 = "STORE found: %d" wide fullword
		$a11 = "POS found: %d" wide fullword
		$a12 = "DOMAIN %s" wide fullword
		$a13 = "/%s/%s/90" wide fullword
		$a14 = "CASH found: %d" wide fullword
		$a15 = "COMPUTERS:" wide fullword
		$a16 = "TERM found: %d" wide fullword

	condition:
		3 of ($a*)
}
