rule Dubnium_Sample_SSHOpenSSL
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "6f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
		hash2 = "feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
		hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
		hash4 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
		hash5 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
		hash6 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "sshkeypairgen.exe" fullword wide
		$s2 = "OpenSSL: FATAL" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <9000KB and all of them
}
