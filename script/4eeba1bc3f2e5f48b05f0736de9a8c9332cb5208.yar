rule malware_seospam_php
{
	meta:
		description = "PHP using Japanese SEO Spam"
		author = "JPCERT/CC Incident Response Group"
		hash = "619cf6a757a1967382287c30d95b55bed3750e029a7040878d2f23efda29f8f0"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$func1 = "function dageget($" ascii
		$func2 = "function sbot()" ascii
		$func3 = "function st_uri()" ascii
		$func4 = "function is_htps()" ascii
		$query1 = /sha1\(sha1\(@\$_GET\[\"(a|\\x61|\\141)"\]\)\);/ ascii
		$query2 = /sha1\(sha1\(@\$_GET\[\"(b|\\x62|\\142)"\]\)\);/ ascii
		$query3 = /@\$_GET\[\"(p|\\x70|\\160)(d|\\x64|\\144)\"\]/ ascii
		$content1 = "nobotuseragent" ascii
		$content2 = "okhtmlgetcontent" ascii
		$content3 = "okxmlgetcontent" ascii
		$content4 = "pingxmlgetcontent" ascii

	condition:
		7 of them
}
