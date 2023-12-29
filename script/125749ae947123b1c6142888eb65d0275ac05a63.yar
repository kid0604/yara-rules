import "pe"

rule INDICATOR_TOOL_SCMalDevInj_Go
{
	meta:
		author = "ditekShen"
		description = "Detects Go shell/malware dev injector"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "hooka/shellcode.go" ascii
		$s2 = "/maldev\x09v" ascii
		$s3 = "Binject/debug/pe." ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
