rule LOG_APT_HAFNIUM_Exchange_Log_Traces_Mar21_1 : LOG
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		date = "2021-03-04"
		score = 65
		os = "windows,linux"
		filetype = "script"

	strings:
		$xr1 = /POST \/(ecp\/y\.js|ecp\/main\.css|ecp\/default\.flt|ecp\/auth\/w\.js|owa\/auth\/w\.js)[^\n]{100,600} (200|301|302) /
		$xr3 = /POST \/owa\/auth\/Current\/[^\n]{100,600} (DuckDuckBot\/1\.0;\+\(\+http:\/\/duckduckgo\.com\/duckduckbot\.html\)|facebookexternalhit\/1\.1\+\(\+http:\/\/www\.facebook\.com\/externalhit_uatext\.php\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\)|Mozilla\/5\.0\+\(compatible;\+Bingbot\/2\.0;\+\+http:\/\/www\.bing\.com\/bingbot\.htm\)|Mozilla\/5\.0\+\(compatible;\+Googlebot\/2\.1;\+\+http:\/\/www\.google\.com\/bot\.html|Mozilla\/5\.0\+\(compatible;\+Konqueror\/3\.5;\+Linux\)\+KHTML\/3\.5\.5\+\(like\+Gecko\)\+\(Exabot-Thumbnails\)|Mozilla\/5\.0\+\(compatible;\+Yahoo!\+Slurp;\+http:\/\/help\.yahoo\.com\/help\/us\/ysearch\/slurp\)|Mozilla\/5\.0\+\(compatible;\+YandexBot\/3\.0;\+\+http:\/\/yandex\.com\/bots\)|Mozilla\/5\.0\+\(X11;\+Linux\+x86_64\)\+AppleWebKit\/537\.36\+\(KHTML,\+like\+Gecko\)\+Chrome\/51\.0\.2704\.103\+Safari\/537\.3)/
		$xr4 = /POST \/ecp\/[^\n]{100,600} (ExchangeServicesClient\/0\.0\.0\.0|python-requests\/2\.19\.1|python-requests\/2\.25\.1)[^\n]{200,600} (200|301|302) /
		$xr5 = /POST \/(aspnet_client|owa)\/[^\n]{100,600} (antSword\/v2\.1|Googlebot\/2\.1\+\(\+http:\/\/www\.googlebot\.com\/bot\.html\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\))[^\n]{200,600} (200|301|302) /

	condition:
		1 of them
}
