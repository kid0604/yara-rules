rule Noderat
{
	meta:
		description = "detect Noderat in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$config = "/config/app.json"
		$key = "/config/.regeditKey.rc"
		$message = "uninstall error when readFileSync: "

	condition:
		all of them
}
