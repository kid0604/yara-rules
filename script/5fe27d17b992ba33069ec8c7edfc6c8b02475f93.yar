rule tick_xxmm_panel
{
	meta:
		description = "xxmm php panel"
		author = "JPCERT/CC Incident Response Group"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sa = "REMOTE_ADDR"
		$sb = "HTTP_USER_AGENT"
		$sc = "$clienttype="
		$sd = "$ccmd="
		$se = "ccc_"
		$sf = "sss_"
		$sg = "|||"

	condition:
		all of them
}
