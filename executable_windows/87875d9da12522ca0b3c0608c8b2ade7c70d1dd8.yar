import "pe"

rule Impacket_Keyword
{
	meta:
		description = "Detects Impacket Keyword in Executable"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-04"
		score = 60
		hash1 = "9388c78ea6a78dbea307470c94848ae2481481f593d878da7763e649eaab4068"
		hash2 = "2f6d95e0e15174cfe8e30aaa2c53c74fdd13f9231406b7103da1e099c08be409"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "impacket.smb(" ascii
		$s2 = "impacket.ntlm(" ascii
		$s3 = "impacket.nmb(" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <14000KB and 1 of them )
}
