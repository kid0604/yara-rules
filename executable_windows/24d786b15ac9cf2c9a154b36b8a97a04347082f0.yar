rule Duqu2_Generic1
{
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample - Generic Rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/7yKyOj"
		date = "2015-06-10"
		super_rule = 1
		hash0 = "3f9168facb13429105a749d35569d1e91465d313"
		hash1 = "0a574234615fb2382d85cd6d1a250d6c437afecc"
		hash2 = "38447ed1d5e3454fe17699f86c0039f30cc64cde"
		hash3 = "5282d073ee1b3f6ce32222ccc2f6066e2ca9c172"
		hash4 = "edfca3f0196788f7fde22bd92a8817a957c10c52"
		hash5 = "6a4ffa6ca4d6fde8a30b6c8739785f4bd2b5c415"
		hash6 = "00170bf9983e70e8dd4f7afe3a92ce1d12664467"
		hash7 = "32f8689fd18c723339414618817edec6239b18f3"
		hash8 = "f860acec9920bc009a1ad5991f3d5871c2613672"
		hash9 = "413ba509e41c526373f991d1244bc7c7637d3e13"
		hash10 = "29cd99a9b6d11a09615b3f9ef63f1f3cffe7ead8"
		hash11 = "dfe1cb775719b529138e054e7246717304db00b1"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Global\\{B54E3268-DE1E-4c1e-A667-2596751403AD}" fullword wide
		$s1 = "SetSecurityDescriptorSacl" fullword ascii
		$s2 = "msisvc_32@" fullword wide
		$s3 = "CompareStringA" fullword ascii
		$s4 = "GetCommandLineW" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
