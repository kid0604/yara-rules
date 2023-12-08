rule ROKRAT_payload : TAU DPRK APT
{
	meta:
		author = "CarbonBlack Threat Research"
		date = "2018-Jan-11"
		description = "Designed to catch loader observed used with ROKRAT malware"
		reference = "https://www.carbonblack.com/2018/02/27/threat-analysis-rokrat-malware/"
		rule_version = 1
		yara_version = "3.7.0"
		TLP = "White"
		exemplar_hashes = "e200517ab9482e787a59e60accc8552bd0c844687cd0cf8ec4238ed2fc2fa573"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "api.box.com/oauth2/token" wide
		$s2 = "upload.box.com/api/2.0/files/content" wide
		$s3 = "api.pcloud.com/uploadfile?path=%s&filename=%s&nopartial=1" wide
		$s4 = "cloud-api.yandex.net/v1/disk/resources/download?path=%s" wide
		$s5 = "SbieDll.dll"
		$s6 = "dbghelp.dll"
		$s7 = "api_log.dll"
		$s8 = "dir_watch.dll"
		$s9 = "def_%s.jpg" wide
		$s10 = "pho_%s_%d.jpg" wide
		$s11 = "login=%s&password=%s&login_submit=Authorizing" wide
		$s12 = "gdiplus.dll"
		$s13 = "Set-Cookie:\\b*{.+?}\\n" wide
		$s14 = "charset={[A-Za-z0-9\\-_]+}" wide

	condition:
		12 of ($s*)
}
