rule BeEF_browser_hooked
{
	meta:
		description = "Yara rule related to hook.js, BeEF Browser hooking capability"
		author = "Pasquale Stirparo"
		date = "2015-10-07"
		hash1 = "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "mitb.poisonAnchor" wide ascii
		$s1 = "this.request(this.httpproto" wide ascii
		$s2 = "beef.logger.get_dom_identifier" wide ascii
		$s3 = "return (!!window.opera" wide ascii
		$s4 = "history.pushState({ Be:\"EF\" }" wide ascii
		$s5 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/10\\./)" wide ascii
		$s6 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/11\\./)" wide ascii
		$s7 = "window.navigator.userAgent.match(/Avant TriCore/)" wide ascii
		$s8 = "window.navigator.userAgent.match(/Iceweasel" wide ascii
		$s9 = "mitb.sniff(" wide ascii
		$s10 = "Method XMLHttpRequest.open override" wide ascii
		$s11 = ".browser.hasWebSocket" wide ascii
		$s12 = ".mitb.poisonForm" wide ascii
		$s13 = "resolved=require.resolve(file,cwd||" wide ascii
		$s14 = "if (document.domain == domain.replace(/(\\r\\n|\\n|\\r)/gm" wide ascii
		$s15 = "beef.net.request" wide ascii
		$s16 = "uagent.search(engineOpera)" wide ascii
		$s17 = "mitb.sniff" wide ascii
		$s18 = "beef.logger.start" wide ascii

	condition:
		all of them
}
