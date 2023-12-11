import "pe"

rule MALWARE_Win_DLInjector04
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader / injector"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Runner" fullword ascii
		$s2 = "DownloadPayload" fullword ascii
		$s3 = "RunOnStartup" fullword ascii
		$a1 = "Antis" fullword ascii
		$a2 = "antiVM" fullword ascii
		$a3 = "antiSandbox" fullword ascii
		$a4 = "antiDebug" fullword ascii
		$a5 = "antiEmulator" fullword ascii
		$a6 = "enablePersistence" fullword ascii
		$a7 = "enableFakeError" fullword ascii
		$a8 = "DetectVirtualMachine" fullword ascii
		$a9 = "DetectSandboxie" fullword ascii
		$a10 = "DetectDebugger" fullword ascii
		$a11 = "CheckEmulator" fullword ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($s*) and 5 of ($a*)) or 10 of ($a*))
}
