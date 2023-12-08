import "pe"

rule APT_RANCOR_PLAINTEE_Variant
{
	meta:
		description = "Detects PLAINTEE malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"
		date = "2018-06-26"
		hash1 = "6aad1408a72e7adc88c2e60631a6eee3d77f18a70e4eee868623588612efdd31"
		hash2 = "bcd37f1d625772c162350e5383903fe8dbed341ebf0dc38035be5078624c039e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "payload.dat" fullword ascii
		$s3 = "temp_microsoft_test.txt" fullword ascii
		$s4 = "reg add %s /v %s /t REG_SZ /d \"%s\"" fullword ascii
		$s6 = "%s %s,helloworld2" fullword ascii
		$s9 = "%s \\\"%s\\\",helloworld" fullword ascii
		$s16 = "recv plugin type %s size:%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 3 of them
}
