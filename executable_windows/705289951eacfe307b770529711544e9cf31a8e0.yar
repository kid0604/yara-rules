import "pe"

rule AnskyaBinderv11Anskya
{
	meta:
		author = "malware-lu"
		description = "Detects Anskya Binder v1.1 Anskya malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [3] 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

	condition:
		$a0 at pe.entry_point
}
