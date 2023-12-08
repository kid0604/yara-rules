import "pe"

rule HKTL_Lazagne_PasswordDumper_Dec18_1
{
	meta:
		description = "Detects password dumper Lazagne often used by middle eastern threat groups"
		author = "Florian Roth (Nextron Systems)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
		date = "2018-12-11"
		score = 85
		hash1 = "1205f5845035e3ee30f5a1ced5500d8345246ef4900bcb4ba67ef72c0f79966c"
		hash2 = "884e991d2066163e02472ea82d89b64e252537b28c58ad57d9d648b969de6a63"
		hash3 = "bf8f30031769aa880cdbe22bc0be32691d9f7913af75a5b68f8426d4f0c7be50"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "softwares.opera(" ascii
		$s2 = "softwares.mozilla(" ascii
		$s3 = "config.dico(" ascii
		$s4 = "softwares.chrome(" ascii
		$s5 = "softwares.outlook(" ascii

	condition:
		uint16(0)==0x5a4d and filesize <17000KB and 1 of them
}
