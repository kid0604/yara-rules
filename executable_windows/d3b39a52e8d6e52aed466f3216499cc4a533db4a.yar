import "pe"

rule Winnti_signing_cert
{
	meta:
		description = "Detects a signing certificate used by the Winnti APT group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/analysis/publications/72275/i-am-hdroot-part-1/"
		date = "2015-10-10"
		score = 75
		hash1 = "a9a8dc4ae77b1282f0c8bdebd2643458fc1ceb3145db4e30120dd81676ff9b61"
		hash2 = "9001572983d5b1f99787291edaadbb65eb2701722f52470e89db2c59def24672"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Guangzhou YuanLuo Technology Co." ascii
		$s2 = "Guangzhou YuanLuo Technology Co.,Ltd" ascii
		$s3 = "$Asahi Kasei Microdevices Corporation0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 1 of them
}
