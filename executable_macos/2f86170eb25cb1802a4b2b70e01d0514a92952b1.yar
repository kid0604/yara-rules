rule CryptHunter_JokerSpy_macos
{
	meta:
		description = "Mach-O malware using CryptHunter"
		author = "JPCERT/CC Incident Response Group"
		hash = "6d3eff4e029db9d7b8dc076cfed5e2315fd54cb1ff9c6533954569f9e2397d4c"
		hash = "951039bf66cdf436c240ef206ef7356b1f6c8fffc6cbe55286ec2792bf7fe16c"
		hash = "d895075057e491b34b0f8c0392b44e43ade425d19eaaacea6ef8c5c9bd3487d8"
		os = "macos"
		filetype = "executable"

	strings:
		$db = "/Library/Application Support/com.apple.TCC/TCC.db" ascii
		$path = "/Users/joker/Downloads/Spy/XProtectCheck/XProtectCheck/" ascii
		$msg1 = "The screen is currently LOCKED!" ascii
		$msg2 = "Accessibility: YES" ascii
		$msg3 = "ScreenRecording: YES" ascii
		$msg4 = "FullDiskAccess: YES" ascii
		$msg5 = "kMDItemDisplayName = *TCC.db" ascii

	condition:
		( uint32(0)==0xfeedface or uint32(0)==0xcefaedfe or uint32(0)==0xfeedfacf or uint32(0)==0xcffaedfe or uint32(0)==0xcafebabe or uint32(0)==0xbebafeca or uint32(0)==0xcafebabf or uint32(0)==0xbfbafeca) and 5 of them
}
