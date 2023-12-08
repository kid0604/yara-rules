import "pe"

rule WiltedTulip_ReflectiveLoader
{
	meta:
		description = "Detects reflective loader (Cobalt Strike) used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "1097bf8f5b832b54c81c1708327a54a88ca09f7bdab4571f1a335cc26bbd7904"
		hash2 = "1f52d643e8e633026db73db55eb1848580de00a203ee46263418f02c6bdb8c7a"
		hash3 = "a159a9bfb938de686f6aced37a2f7fa62d6ff5e702586448884b70804882b32f"
		hash4 = "cf7c754ceece984e6fa0d799677f50d93133db609772c7a2226e7746e6d046f0"
		hash5 = "eee430003e7d59a431d1a60d45e823d4afb0d69262cc5e0c79f345aa37333a89"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
		$x2 = "%d is an x86 process (can't inject x64 content)" fullword ascii
		$x3 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
		$x4 = "Failed to impersonate token from %d (%u)" fullword ascii
		$x5 = "Failed to impersonate logged on user %d (%u)" fullword ascii
		$x6 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of them ) or (2 of them ) or pe.exports("_ReflectiveLoader@4")
}
