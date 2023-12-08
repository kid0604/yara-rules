import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_AntiVM_WMIC
{
	meta:
		author = "ditekSHen"
		description = "Detects memory artifcats referencing WMIC commands for anti-VM checks"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "wmic process where \"name like '%vmwp%'\"" ascii wide nocase
		$s2 = "wmic process where \"name like '%virtualbox%'\"" ascii wide nocase
		$s3 = "wmic process where \"name like '%vbox%'\"" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 2 of them
}
