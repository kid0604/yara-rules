import "pe"

rule MALWARE_Win_GoBrutLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects GoBrut StealthWorker laoder"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and pe.exports("@SetFirstEverVice@8")
}
