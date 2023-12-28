rule tick_daserf_mmid
{
	meta:
		description = "Daserf malware (Delphi)"
		author = "JPCERT/CC Incident Response Group"
		hash = "94a9a9e14acaac99f7a980d36e57a451fcbce3bb4bf24e41f53d751c062e60e5"
		os = "windows"
		filetype = "executable"

	strings:
		$ua = /Mozilla\/\d.0 \(compatible; MSIE \d{1,2}.0; Windows NT 6.\d; SV1\)/
		$delphi = "Delphi"
		$mmid = "MMID"
		$ccaacmds = "ccaacmds"
		$php = ".php"

	condition:
		$ua and $delphi and #php>3 and $mmid and $ccaacmds
}
