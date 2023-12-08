rule scanarator
{
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
		os = "windows"
		filetype = "executable"

	strings:
		$s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"

	condition:
		all of them
}
