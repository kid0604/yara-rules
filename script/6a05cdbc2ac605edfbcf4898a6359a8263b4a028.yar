import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery
{
	meta:
		author = "ditekSHen"
		description = "Detects JS potentially executing WMI queries"
		os = "windows"
		filetype = "script"

	strings:
		$ex = ".ExecQuery(" ascii nocase
		$s1 = "GetObject(" ascii nocase
		$s2 = "String.fromCharCode(" ascii nocase
		$s3 = "ActiveXObject(" ascii nocase
		$s4 = ".Sleep(" ascii nocase

	condition:
		($ex and all of ($s*))
}
